# Evaluation checks of the module: the demo personas and variants of the
# reference system, evaluated with the current module and the current feed.
# Nothing is built; each check fails evaluation with the list of what is wrong.
{
  self,
  nixpkgs,
  pkgs,
}:
let
  inherit (nixpkgs) lib;
  source = lib.importJSON ../vex/baseline.openvex.json;
  ids = builtins.map (st: st."@id") source.statements;

  persona =
    name: extra:
    (nixpkgs.lib.nixosSystem {
      modules = [
        ../demo/${name}/configuration.nix
        self.nixosModules.default
      ]
      ++ extra;
    }).config;
  baseline = extra: (self.nixosConfigurations.baseline.extendModules { modules = extra; }).config;

  # A passing check is an empty list of failures.
  check =
    name: failures:
    assert lib.assertMsg (
      failures == [ ]
    ) "nixos-vex check ${name}:\n  ${lib.concatStringsSep "\n  " failures}";
    pkgs.runCommand "nixos-vex-${name}" { } "touch $out";
  expectEq =
    what: expected: actual:
    lib.optional (
      expected != actual
    ) "${what}: expected ${builtins.toJSON expected}, got ${builtins.toJSON actual}";

  droppedIds = cfg: lib.unique (lib.concatLists (builtins.attrValues cfg.nixosVex.dropped));
  markedWith = cfg: c: builtins.filter (id: lib.elem c cfg.nixosVex.markers.${id}) ids;

  # pkg:nix/<name>[@<version>] -> { name; version (null when versionless); }
  parsePurl =
    purl:
    let
      parts = lib.splitString "@" (lib.removePrefix "pkg:nix/" purl);
    in
    {
      name = builtins.head parts;
      version = if builtins.length parts > 1 then builtins.elemAt parts 1 else null;
    };
  # Two products overlap when a scanner finding could match both: same
  # package, and a versionless purl or the same version.
  overlaps =
    a: b:
    let
      pa = parsePurl a."@id";
      pb = parsePurl b."@id";
    in
    pa.name == pb.name && (pa.version == null || pb.version == null || pa.version == pb.version);
  suppresses =
    st:
    lib.elem st.status [
      "not_affected"
      "fixed"
    ];

  # What must hold for every system, derived from the data alone.
  consistency =
    cfg:
    let
      inherit (cfg.nixosVex) conditions markers dropped;
      failingIds = builtins.filter (id: lib.any (c: !conditions.${c}) markers.${id}) ids;
      kept = cfg.nixosVex.generated.statements;
      droppedStatements = builtins.filter (st: lib.elem st."@id" (droppedIds cfg)) source.statements;
      shadowing = lib.concatMap (
        d:
        builtins.map (k: "${d."@id"} is dropped, but ${k."@id"} still suppresses its finding") (
          builtins.filter (
            k:
            suppresses k
            && k.vulnerability.name == d.vulnerability.name
            && lib.any (pk: lib.any (overlaps pk) d.products) k.products
          ) kept
        )
      ) droppedStatements;
    in
    # Dropped are exactly the statements with a failing condition, listed
    # under each failing condition they name.
    expectEq "dropped statements" failingIds (lib.filter (id: lib.elem id (droppedIds cfg)) ids)
    ++ lib.concatLists (
      lib.mapAttrsToList (
        c: dids:
        expectEq "statements dropped by ${c}" (lib.filter (id: lib.elem id failingIds) (
          markedWith cfg c
        )) dids
      ) dropped
    )
    # The generated feed is the source minus the dropped statements, in order.
    ++ expectEq "generated feed" (lib.subtractLists failingIds ids) (builtins.map (st: st."@id") kept)
    # Leaving a statement out must bring its finding back.
    ++ shadowing;

  # Each system with the conditions expected to fail. Persona expectations
  # were reviewed once; the variants drop exactly their guard's statements.
  systems = {
    baseline = {
      cfg = baseline [ ];
      failing = [ ];
    };
    desktop = {
      cfg = persona "desktop" [ ];
      failing = [
        "fs-xfs-not-mounted"
        "no-user-mounts"
        "sshd-no-opie"
        "sshd-no-password-auth"
      ];
    };
    desktop-no-udisks = {
      cfg = persona "desktop" [ { services.udisks2.enable = lib.mkForce false; } ];
      failing = [
        "fs-xfs-not-mounted"
        "sshd-no-opie"
        "sshd-no-password-auth"
      ];
    };
    server = {
      cfg = persona "server" [ ];
      failing = [ ];
    };
    baseline-aarch64 = {
      cfg = baseline [ { nixpkgs.hostPlatform = lib.mkForce "aarch64-linux"; } ];
      failing = [ "x86-64" ];
    };
    baseline-latest-kernel = {
      cfg = baseline [ ({ pkgs, ... }: { boot.kernelPackages = pkgs.linuxPackages_latest; }) ];
      failing = [ "stock-kernel" ];
    };
  };

  systemChecks = lib.mapAttrs' (
    name: s:
    lib.nameValuePair "system-${name}" (
      check "system-${name}" (
        expectEq "failing conditions" s.failing (builtins.attrNames s.cfg.nixosVex.dropped)
        ++ consistency s.cfg
      )
    )
  ) systems;

  desktop = systems.desktop.cfg;
  desktopStrict = persona "desktop" [ { nixosVex.strict = true; } ];
  noHostname = baseline [ { networking.hostName = ""; } ];
  isOurs = lib.hasPrefix "nixos-vex:";
in
systemChecks
// {
  # Every condition is used by a statement (unknown ones fail evaluation).
  conditions =
    let
      cfg = systems.baseline.cfg;
      used = lib.unique (lib.concatLists (builtins.attrValues cfg.nixosVex.markers));
    in
    check "conditions" (
      expectEq "conditions used by no statement" [ ] (
        builtins.filter (c: !(lib.elem c used)) (builtins.attrNames cfg.nixosVex.conditions)
      )
    );

  # Strict mode turns the warning into a failing assertion with the same text.
  strict = check "strict" (
    expectEq "nixos-vex warnings in strict mode" [ ] (builtins.filter isOurs desktopStrict.warnings)
    ++ expectEq "failing assertions in strict mode" (builtins.filter isOurs desktop.warnings) (
      builtins.map (a: a.message) (
        builtins.filter (a: !a.assertion && isOurs a.message) desktopStrict.assertions
      )
    )
  );

  # An empty hostName (taken from DHCP) leaves the host out of the feed's @id.
  hostname-empty = check "hostname-empty" (
    expectEq "feed @id" "${source."@id"}#generated" noHostname.nixosVex.generated."@id"
  );
}
