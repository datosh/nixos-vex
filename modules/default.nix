{
  config,
  lib,
  pkgs,
  ...
}:

# Builds the VEX feed for THIS system (system.build.vexFeed).
#
# Unconditional statements of the feed are always included. A statement that
# only holds under a configuration assumption names its condition with a
# `[nixos-vex:condition=<id>]` marker in status_notes; it is included only
# while that condition holds for this configuration. Statements left out are
# reported as evaluation warnings (or failures with nixosVex.strict), and
# their findings reappear in the scan for the user to triage.
#
# The statements are analysis, not guarantees: see the Disclaimer in README.md.
let
  cfg = config.nixosVex;
  sshd = config.services.openssh;
  nm = config.networking.networkmanager;

  # An sshd built with GSSAPI/Kerberos support: the openssh_gssapi package,
  # or an overlay adding a distro GSSAPI patch to openssh.
  hasGssapi =
    pkg:
    lib.any (p: lib.hasInfix "gssapi" (baseNameOf (toString p))) (pkg.patches or [ ])
    || lib.any (lib.hasPrefix "--with-kerberos5") (pkg.configureFlags or [ ]);
  hasPname = name: lib.any (p: (p.pname or "") == name);
  # Packages the configuration installs or puts on a service's PATH. Not the
  # whole closure: a package referenced only through a store path in a script
  # or unit stays invisible to evaluation.
  declaredPackages =
    config.environment.systemPackages
    ++ lib.concatMap (u: u.packages) (lib.attrValues config.users.users)
    ++ config.systemd.packages
    ++ lib.concatMap (s: s.path) (lib.attrValues config.systemd.services)
    ++ lib.concatMap (s: s.path) (lib.attrValues config.systemd.user.services);
  # The kernel the feed was triaged against: nixpkgs' default linuxPackages,
  # unmodified. Compared with a fresh import of the same nixpkgs, so an
  # overlay that changes linuxPackages does not count as stock.
  pristineKernel =
    (import pkgs.path { localSystem = pkgs.stdenv.hostPlatform.system; }).linuxPackages.kernel;
  userControlled =
    let
      u = config.networking.wireless.userControlled;
    in
    if builtins.isBool u then u else u.enable or false;
  sysctlIs = name: values: lib.elem (config.boot.kernel.sysctl.${name} or null) values;

  # Filesystem types this system can mount without a user's own root action:
  # declared mounts, plus anything once an automounter is configured. "auto"
  # probes the device, so it may become any type.
  mountedTypes =
    builtins.map (fs: fs.fsType) (lib.attrValues config.fileSystems)
    ++ builtins.map (m: m.type or "") config.systemd.mounts;
  canMount =
    types: config.services.autofs.enable || lib.any (t: t == "auto" || lib.elem t types) mountedTypes;
  kernelModules = config.boot.kernelModules ++ config.boot.initrd.kernelModules;

  # One "<type> is never mounted" condition per filesystem whose kernel code is
  # only reachable through a mount (none of them allows user-namespace mounts).
  fsConditions =
    lib.mapAttrs'
      (
        name: types:
        lib.nameValuePair "fs-${name}-not-mounted" {
          holds = !canMount types;
          reason = "${name} can be mounted (fileSystems, systemd.mounts or services.autofs)";
        }
      )
      {
        xfs = [ "xfs" ];
        hfs = [ "hfs" ];
        btrfs = [ "btrfs" ];
        gfs2 = [
          "gfs2"
          "gfs2meta"
        ];
        udf = [ "udf" ];
        f2fs = [ "f2fs" ];
        erofs = [ "erofs" ];
        jfs = [ "jfs" ];
        afs = [ "afs" ];
        cifs = [
          "cifs"
          "smb3"
        ];
      };

  # Every condition: does it hold for this configuration, what breaks it,
  # and (optionally) the change that restores it.
  conditions = fsConditions // {
    x86-64 = {
      # Kernel build configuration and architecture-specific code differ per
      # platform; the feed is triaged for x86_64-linux only.
      holds = pkgs.stdenv.hostPlatform.system == "x86_64-linux";
      reason = "the system is not x86_64-linux (nixpkgs.hostPlatform)";
    };
    stock-kernel = {
      # Verdicts about what the kernel builds rest on nixpkgs' kernel config;
      # a different kernel package, kernel patches or config changes void them.
      holds =
        builtins.unsafeDiscardStringContext config.boot.kernelPackages.kernel.drvPath
        == builtins.unsafeDiscardStringContext pristineKernel.drvPath;
      reason = "the kernel is not nixpkgs' default kernel, unmodified (boot.kernelPackages, boot.kernelPatches, overlays)";
      fix = "boot.kernelPackages = pkgs.linuxPackages; with no boot.kernelPatches";
    };
    nvme-nodes-privileged = {
      # NVMe passthrough I/O commands are allowed without CAP_SYS_ADMIN to
      # whoever can open the device node: the generic char nodes (/dev/ngXnY)
      # are root-only, the block nodes root:disk. Extra udev rules may widen
      # that; rules shipped in services.udev.packages are not inspected.
      holds =
        let
          rules = lib.toLower config.services.udev.extraRules;
        in
        # "ng: the generic char node names (KERNEL=="ng*"); errs towards failing.
        !(lib.hasInfix "nvme" rules) && !(lib.hasInfix "\"ng" rules);
      reason = "udev rules mention NVMe device nodes (services.udev.extraRules)";
    };
    lsm-without-selinux = {
      # NixOS boots with lsm= from security.lsm, which does not include
      # SELinux, so selinuxfs is never registered.
      holds =
        !(lib.elem "selinux" config.security.lsm)
        && !(lib.any (
          p: (lib.hasPrefix "lsm=" p && lib.hasInfix "selinux" p) || p == "security=selinux"
        ) config.boot.kernelParams);
      reason = "SELinux is enabled (security.lsm or boot.kernelParams)";
    };
    ksm-disabled = {
      holds = !config.hardware.ksm.enable;
      reason = "kernel samepage merging is enabled (hardware.ksm.enable)";
    };
    coredump-piped = {
      # systemd-coredump receives cores through an absolute pipe; a relative
      # core_pattern lets a core land in an attacker-chosen directory.
      holds =
        config.systemd.coredump.enable
        && (
          let
            p = config.boot.kernel.sysctl."kernel.core_pattern" or null;
          in
          p == null || lib.hasPrefix "|" p
        );
      reason = "core dumps are not piped to systemd-coredump (systemd.coredump.enable, kernel.core_pattern)";
      fix = "keep systemd.coredump.enable = true; and leave kernel.core_pattern unset";
    };
    kaslr-enabled = {
      holds = !(lib.elem "nokaslr" config.boot.kernelParams);
      reason = "KASLR disabled (nokaslr in boot.kernelParams)";
    };
    no-user-mounts = {
      # udisks2 lets the active local user mount removable media of any type.
      holds = !config.services.udisks2.enable;
      reason = "users can mount removable media (services.udisks2.enable)";
      fix = "services.udisks2.enable = false; (where nobody needs to mount removable media)";
    };
    netfs-unused = {
      # Consumers of the kernel's netfs library (modules.dep of the 6.18
      # kernel): 9p, afs, ceph, cifs/smb3, nfs (with NFS_FSCACHE), cachefiles.
      holds =
        !canMount [
          "9p"
          "afs"
          "ceph"
          "cifs"
          "smb3"
          "nfs"
          "nfs4"
        ]
        && !config.services.cachefilesd.enable;
      reason = "a netfs-based filesystem can be mounted (9p, afs, ceph, cifs, nfs; fileSystems, systemd.mounts, services.autofs, services.cachefilesd)";
    };
    cachefiles-unused = {
      # cachefiles acts only once a daemon binds a cache through
      # /dev/cachefiles (CAP_SYS_ADMIN); the device is not autoloaded, so a
      # daemon set up outside services.cachefilesd usually loads the module
      # through boot.kernelModules.
      holds = !config.services.cachefilesd.enable && !(lib.elem "cachefiles" kernelModules);
      reason = "a cachefiles cache can be bound (services.cachefilesd, cachefiles in boot.kernelModules)";
      fix = "services.cachefilesd.enable = false; (where no network filesystem cache is needed)";
    };
    ceph-unused = {
      holds =
        !canMount [ "ceph" ]
        && !(lib.any (d: config.services.ceph.${d}.enable) [
          "mon"
          "osd"
          "mgr"
          "mds"
          "rgw"
          "client"
        ])
        && !(lib.elem "rbd" kernelModules);
      reason = "Ceph is used (ceph mount, services.ceph, or the rbd module)";
    };
    ksmbd-not-configured = {
      # ksmbd's control netlink needs CAP_NET_ADMIN and the module has no
      # autoload alias: it only runs once root loads and starts it.
      holds = !(lib.elem "ksmbd" kernelModules) && !(hasPname "ksmbd-tools" declaredPackages);
      reason = "the in-kernel SMB server ksmbd is configured (boot.kernelModules, or ksmbd-tools installed or on a service path)";
    };
    sshd-no-opie = {
      holds =
        !sshd.enable
        || (
          # (1) no OPIE package exists in the package set (nixpkgs or overlay),
          !(pkgs ? opie)
          && !(pkgs ? pam_opie)
          # (2) the PAM challenge-response path is disabled in sshd,
          && sshd.settings.KbdInteractiveAuthentication == false
          # (3) no sshd PAM auth rule loads an OPIE module.
          && !(lib.any (rule: rule.enable && lib.hasInfix "opie" rule.modulePath) (
            lib.attrValues config.security.pam.services.sshd.rules.auth
          ))
        );
      reason = "sshd OPIE authentication possible (services.openssh.settings.KbdInteractiveAuthentication)";
      fix = "services.openssh.settings.KbdInteractiveAuthentication = false; and no OPIE module in the sshd PAM stack";
    };
    sshd-no-gssapi = {
      holds = !sshd.enable || !hasGssapi sshd.package;
      reason = "sshd built with GSSAPI/Kerberos (services.openssh.package)";
    };
    sshd-no-password-auth = {
      holds = !sshd.enable || sshd.settings.PasswordAuthentication == false;
      reason = "sshd password authentication enabled (services.openssh.settings.PasswordAuthentication)";
      fix = "services.openssh.settings.PasswordAuthentication = false; (key-based login only)";
    };
    dhcpcd-not-running = {
      # dhcpcd is in the closure only as NetworkManager's optional backend.
      holds = !(config.systemd.services.dhcpcd.enable or false) && !(nm.enable && nm.dhcp == "dhcpcd");
      reason = "dhcpcd runs as DHCP client (networking.dhcpcd / networking.networkmanager.dhcp)";
    };
    nix-no-recursive-nix = {
      holds =
        !(lib.elem "recursive-nix" (config.nix.settings.experimental-features or [ ]))
        && !(lib.hasInfix "recursive-nix" config.nix.extraOptions);
      reason = "nix recursive-nix feature enabled (nix.settings.experimental-features)";
      fix = "do not enable the recursive-nix experimental feature";
    };
    no-full-busybox = {
      # Only Nix's sandbox shell (ash/sh applets) may be present; the full
      # busybox shares its purl but ships the netstat and tar applets.
      holds = !(hasPname "busybox" declaredPackages);
      reason = "full busybox installed (environment.systemPackages, users.users.*.packages, systemd.packages or a service path)";
    };
    no-legacy-tiocsti = {
      holds =
        !(sysctlIs "dev.tty.legacy_tiocsti" [
          1
          "1"
          true
        ]);
      reason = "legacy TIOCSTI re-enabled (boot.kernel.sysctl.\"dev.tty.legacy_tiocsti\")";
      fix = "leave dev.tty.legacy_tiocsti at its default (0)";
    };
    no-p11-kit-server = {
      holds =
        !(config.systemd.user.sockets ? p11-kit-server)
        && !(config.systemd.user.services ? p11-kit-server)
        && !(hasPname "p11-kit" config.systemd.packages);
      reason = "p11-kit RPC server enabled (systemd.user / systemd.packages)";
    };
    wpa-supplicant-root-only = {
      holds =
        (config.users.groups.wpa_supplicant.members or [ ]) == [ ]
        && !(lib.any (u: lib.elem "wpa_supplicant" u.extraGroups) (lib.attrValues config.users.users))
        && !userControlled;
      reason = "non-root principals can control wpa_supplicant (wpa_supplicant group, networking.wireless.userControlled)";
    };
    no-privileged-strace = {
      holds =
        !(lib.any (w: lib.hasSuffix "/strace" (toString w.source) && (w.setuid || w.capabilities != "")) (
          lib.attrValues config.security.wrappers
        ));
      reason = "privileged strace wrapper (security.wrappers)";
      fix = "do not install strace setuid or with file capabilities";
    };
    nscd-is-nsncd = {
      # NixOS runs nsncd in place of glibc's nscd by default.
      holds = !(config.services.nscd.enable && !config.services.nscd.enableNsncd);
      reason = "glibc nscd runs instead of nsncd (services.nscd.enableNsncd)";
      fix = "keep services.nscd.enableNsncd = true;";
    };
    protected-hardlinks = {
      # systemd's 50-default.conf sets fs.protected_hardlinks = 1.
      holds =
        !(sysctlIs "fs.protected_hardlinks" [
          0
          "0"
          false
        ]);
      reason = "hardlink protection disabled (boot.kernel.sysctl.\"fs.protected_hardlinks\")";
      fix = "leave fs.protected_hardlinks at systemd's default (1)";
    };
  };

  source = lib.importJSON cfg.feed;

  # Condition ids named by a statement's markers; an unknown id fails closed.
  conditionsOf =
    st:
    let
      # builtins.split yields the capture groups of each match as a list.
      found = builtins.map builtins.head (
        builtins.filter builtins.isList (
          builtins.split "\\[nixos-vex:condition=([a-z0-9-]+)]" (st.status_notes or "")
        )
      );
    in
    builtins.map (
      id:
      if conditions ? ${id} then
        id
      else
        throw "nixos-vex: statement ${st."@id"} names unknown condition '${id}'"
    ) found;

  # Statement @id -> the condition ids its markers name.
  markers = lib.listToAttrs (
    builtins.map (st: lib.nameValuePair st."@id" (conditionsOf st)) source.statements
  );
  statementsById = lib.listToAttrs (
    builtins.map (st: lib.nameValuePair st."@id" st) source.statements
  );

  applies = st: lib.all (id: conditions.${id}.holds) markers.${st."@id"};
  kept = builtins.filter applies source.statements;
  dropped = builtins.filter (st: !(applies st)) source.statements;

  # Failing condition id -> the @ids of the statements it drops (feed order).
  # Conditions that fail without dropping anything are left out.
  droppedBy = lib.filterAttrs (_: ids: ids != [ ]) (
    lib.mapAttrs (
      id: _: builtins.map (st: st."@id") (builtins.filter (st: lib.elem id markers.${st."@id"}) dropped)
    ) (lib.filterAttrs (_: c: !c.holds) conditions)
  );

  # Failing conditions that actually drop statements, with their CVEs.
  failing = lib.mapAttrsToList (id: ids: {
    inherit (conditions.${id}) reason;
    fix = conditions.${id}.fix or null;
    statements = builtins.map (sid: statementsById.${sid}) ids;
  }) droppedBy;

  describe =
    st:
    let
      product = builtins.head (
        lib.splitString "@" (lib.removePrefix "pkg:nix/" (builtins.head st.products)."@id")
      );
    in
    "${st.vulnerability.name} (${product})";
  report = lib.concatMapStrings (
    c:
    "\n  - ${c.reason}\n      ${lib.concatMapStringsSep " " describe c.statements}"
    + lib.optionalString (c.fix != null) "\n      restore with: ${c.fix}"
  ) failing;
  summary =
    "nixos-vex: ${toString (builtins.length dropped)} statement(s) not applicable to this system:"
    + report
    + "\n  Their findings will appear in your scan; triage them in your own VEX document.";

  feed = source // {
    # networking.hostName may be empty (taken from DHCP at runtime).
    "@id" =
      "${source."@id"}#generated"
      + lib.optionalString (config.networking.hostName != "") "-for-${config.networking.hostName}";
    statements = kept;
  };
in
{
  options.nixosVex = {
    feed = lib.mkOption {
      type = lib.types.path;
      default = ../vex/baseline.openvex.json;
      description = "OpenVEX source document the per-system feed is generated from.";
    };
    strict = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Fail evaluation when a condition does not hold, instead of leaving its
        statements out of the feed with a warning.
      '';
    };
    conditions = lib.mkOption {
      type = lib.types.attrsOf lib.types.bool;
      readOnly = true;
      internal = true;
      description = "Whether each condition holds (for tests and consistency checks).";
    };
    markers = lib.mkOption {
      type = lib.types.attrsOf (lib.types.listOf lib.types.str);
      readOnly = true;
      internal = true;
      description = "Statement `@id` -> the condition ids named by its `[nixos-vex:condition=<id>]` markers.";
    };
    generated = lib.mkOption {
      type = lib.types.attrs;
      readOnly = true;
      internal = true;
      description = "The generated feed document, as written to `system.build.vexFeed` (for tests).";
    };
    dropped = lib.mkOption {
      type = lib.types.attrsOf (lib.types.listOf lib.types.str);
      readOnly = true;
      description = ''
        Statements left out of this system's feed: each failing condition
        mapped to the `@id`s of the statements it drops. A statement with
        several failing conditions is listed under each. Empty when every
        statement applies.
      '';
    };
  };

  config = {
    nixosVex = {
      conditions = lib.mapAttrs (_: c: c.holds) conditions;
      inherit markers;
      generated = feed;
      dropped = droppedBy;
    };
    system.build.vexFeed = pkgs.writeText "nixos-vex.openvex.json" (builtins.toJSON feed);
    warnings = lib.optional (!cfg.strict && dropped != [ ]) summary;
    assertions = [
      {
        assertion = !cfg.strict || dropped == [ ];
        message = summary;
      }
    ];
  };
}
