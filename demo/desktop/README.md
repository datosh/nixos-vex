# Demo: desktop

This folders contains a desktop-like configuration to demonstrate how to
use nixos-vex to triage CVEs.

A desktop might have the following configuration options which impact
assumptions made in our feed:

* `services.udisks2.enable = true` allows users to easily mount disks, e.g., USB sticks,
  of **any filesystem** from the file manager. This would be enabled by GNOME and Plasma for you.
* An xfs `fileSystems` entry for a `/data` disk.
* `services.openssh.enable = true` enables other defaults such as `PasswordAuthentication`
  and `KbdInteractiveAuthentication`.

## 1. Build the feed for this system

```sh
nix build ./demo/desktop#nixosConfigurations.desktop.config.system.build.vexFeed -o vex-feed.json
```

Evaluation will list every broken assumption and their related CVEs:

```
nixos-vex: 11 statement(s) not applicable to this system:
  - xfs can be mounted (fileSystems, systemd.mounts or services.autofs)
      CVE-2026-43053 (linux)
  - users can mount removable media (services.udisks2.enable)
      CVE-2023-3397 (linux) CVE-2026-43053 (linux) CVE-2026-43228 (linux) CVE-2026-43299 (linux) CVE-2026-43308 (linux) CVE-2026-45961 (linux) CVE-2026-45991 (linux) CVE-2026-53017 (linux) CVE-2026-64146 (linux)
      restore with: services.udisks2.enable = false; (where nobody needs to mount removable media)
  - sshd OPIE authentication possible (services.openssh.settings.KbdInteractiveAuthentication)
      CVE-2007-2768 (openssh)
      restore with: services.openssh.settings.KbdInteractiveAuthentication = false; and no OPIE module in the sshd PAM stack
  - sshd password authentication enabled (services.openssh.settings.PasswordAuthentication)
      CVE-2023-51767 (openssh)
      restore with: services.openssh.settings.PasswordAuthentication = false; (key-based login only)
  Their findings will appear in your scan; triage them in your own VEX document.
```

A statement can depend on several conditions, e.g., CVE-2026-43053 needs both "xfs
is never mounted" and "no user mounts", and is listed under each failing condition.
The same data is available as `config.nixosVex.dropped`.

## 2. Scan

```sh
nix run github:tiiuae/sbomnix -- \
  ./demo/desktop#nixosConfigurations.desktop.config.system.build.toplevel --cdx sbom.cdx.json

grype sbom:sbom.cdx.json --vex vex-feed.json
```

The findings above are still active in grype's output. grype suppresses only
`not_affected` and `fixed` statements. `affected` statements in the feed stay
visible, enhanced with their `action_statement`.

## 3. Triage the remaining findings

Each remaining finding is now a decision for the owner of this machine.

### 3.1. Hardening the Nix Configuration

Where possible we provide "restore with" hints: a configuration change that
brings statements back. Let's assume this desktop does not need to mount USB sticks,
so it follows the udisks2 hint:

```nix
services.udisks2.enable = false;
```

The 9 udisks-dependent statements return at the next evaluation. Only the
xfs and the two sshd statements stay dropped:

```
nixos-vex: 3 statement(s) not applicable to this system:
  - xfs can be mounted (fileSystems, systemd.mounts or services.autofs)
      CVE-2026-43053 (linux)
  - sshd OPIE authentication possible (services.openssh.settings.KbdInteractiveAuthentication)
      CVE-2007-2768 (openssh)
      restore with: services.openssh.settings.KbdInteractiveAuthentication = false; and no OPIE module in the sshd PAM stack
  - sshd password authentication enabled (services.openssh.settings.PasswordAuthentication)
      CVE-2023-51767 (openssh)
      restore with: services.openssh.settings.PasswordAuthentication = false; (key-based login only)
  Their findings will appear in your scan; triage them in your own VEX document.
```

### 3.2. Custom VEX Statements

The owner wants to keep password login over ssh and the xfs data disk. With
the additional understanding of how this system is used, they record their own
verdicts for the three remaining findings in `desktop.openvex.json`:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.org/desktop.openvex.json",
  "author": "desktop owner",
  "timestamp": "2026-10-06T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": { "name": "CVE-2026-43053" },
      "products": [{ "@id": "pkg:nix/linux@6.18.54" }],
      "status": "not_affected",
      "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
      "impact_statement": "xfs crash window during attr inactivation. The only xfs filesystem is /data, an internal disk I formatted myself; with udisks2 disabled no other xfs filesystem can be mounted, so its contents are never attacker-supplied."
    },
    {
      "vulnerability": { "name": "CVE-2007-2768" },
      "products": [{ "@id": "pkg:nix/openssh" }],
      "status": "not_affected",
      "justification": "vulnerable_code_not_present",
      "impact_statement": "Username enumeration through OPIE. Keyboard-interactive login stays enabled, but the sshd PAM stack (security.pam.services.sshd) loads no OPIE module and none is installed."
    },
    {
      "vulnerability": { "name": "CVE-2023-51767" },
      "products": [{ "@id": "pkg:nix/openssh" }],
      "status": "not_affected",
      "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
      "impact_statement": "Rowhammer bit flip during sshd password authentication; it needs an attacker already running code on this machine. The only local account is my own, so such an attacker already controls my session."
    }
  ]
}
```

Both VEX documents can be supplied to grype:

```sh
grype sbom:sbom.cdx.json --vex vex-feed.json --vex desktop.openvex.json
```

The system now has zero untriaged findings. The findings that stay visible
are covered by the feed's `affected` statements; their `action_statement`
says which fix to wait for, and what to do until then.
