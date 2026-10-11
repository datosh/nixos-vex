# Demo: server

A hardened server that uses nixos-vex in strict mode.

A server can make more assumptions about its hardware and is less
concerned about everyday convenience, allowing for more hardening.

A server might have the following configuration options which impact
assumptions made in our feed:

* `networking.useNetworkd = true` enables DHCP in systemd-networkd, otherwise dhcpcd related CVEs would show up.
* Disabling password authentication `services.openssh.settings.PasswordAuthentication = false` and 
  PAM challenge and response `services.openssh.settings.KbdInteractiveAuthentication = false`
  gets rid of openssh CVEs
* Disabling `services.udisks2` is possible, because server hardware is usually static.

## Build the feed and scan

```sh
nix build ./demo/server#nixosConfigurations.server.config.system.build.vexFeed -o vex-feed.json
```

Evaluation emits no nixos-vex warnings, and we can see that `config.nixosVex.dropped`
is `{ }`. At this point we can enable strict mode to fail to keep it that way:

```nix
nixosVex.strict = true;
```

Finally we scan:

```sh
nix run github:tiiuae/sbomnix -- \
  ./demo/server#nixosConfigurations.server.config.system.build.toplevel --cdx sbom.cdx.json

grype sbom:sbom.cdx.json --vex vex-feed.json
```
