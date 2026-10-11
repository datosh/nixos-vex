# nixos-vex

A VEX feed for NixOS built on [sbomnix](https://github.com/tiiuae/sbomnix)
and [grype](https://github.com/anchore/grype) to provide a
[common baseline](./hosts/baseline/configuration.nix)
and aid in triage decisions, evaluated against *your* configuration.

Currently this feed only targets
[nixos-unstable](https://wiki.nixos.org/wiki/Channel_branches) for `x86_64` systems.

## How it works

`sbomnix` generates an SBOM for a basic (unmodified `nixos-generate-config`)
NixOS configuration pinned against the latest version of the `nixos-unstable` channel.
`grype` is then used to scan for CVEs for packages in the NixOS system. The
problem is that many of the reported CVEs do not apply, due to various reasons:
+ wrong upstream data
+ code that is not built
+ code only runs in configurations you don't have
+ and many more...

This project records decisions as [OpenVEX](https://openvex.dev) statements,
so `grype` correctly suppresses them. The goal of this VEX feed is **not zero CVEs**,
but zero untriaged CVEs. It gets rid of false positives, and helps you handle the rest.

We generally have two types of statements:

**Unconditional statements** are true for every NixOS system, e.g., "the CVE
exists only in a Red Hat patch", or "the CVE data doesn't report fixed versions
correctly".

**Conditional statements** make assumptions about your configuration. For example
"ssh password auth is disabled" or "xfs is never mounted". The awesome thing about
NixOS is, we can check these programmatically!

Our NixOS module evaluates every condition against your configuration and builds
a feed containing only the statements that are true for *your* system 
(`system.build.vexFeed`). 

When a statement fails, we emit a warning and hand the triage decision back to you.
Where possible, we attach supporting information, such as ways to mitigate the CVE.
A conditional statement is linked to its condition with a `[nixos-vex:condition=<id>]`
marker, in VEX statement's `status_notes` field.

## Usage

Add the flake input and import the module:

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixos-vex.url = "github:datosh/nixos-vex";
  };

  outputs = { nixpkgs, nixos-vex, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        ./configuration.nix
        nixos-vex.nixosModules.default # adds system.build.vexFeed
      ];
    };
  };
}
```

Then build your feed and pass it to grype next to your SBOM:

```sh
nix build .#nixosConfigurations.myhost.config.system.build.vexFeed -o vex-feed.json
grype sbom:sbom.cdx.json --vex vex-feed.json
```

See the demo folder for two examples of different machine configurations using
nixos-vex:

- [`demo/desktop`](./demo/desktop/README.md) is a minimal desktop environment
  that uses udisks2, an xfs data disk and sshd with NixOS's defaults. The demo
  walks through triaging them in your own VEX document.
- [`demo/server`](./demo/server/README.md) has known hardware, key-only ssh and
  systemd-networkd. Due to the hardened config, every statement holds, and we can
  enable strict mode to keep it that way.

## Disclaimer

nixos-vex is a personal project. It is not affiliated with NixOS, nixpkgs or
any of the other projects used.

Every statement in the feed was created based on the analysis of public
information (CVE records, upstream source, nixpkgs) available at the time.
Some statements were created deterministically based on various data sources,
other's were suggested by LLM agents and signed-off by a human (that's me).
A statement always carries judgement and data may be interpreted wrong.

The feed only covers packages of [the reference
system](./hosts/baseline/configuration.nix). Packages your system adds beyond
it are not triaged.

[The conditions](./modules/default.nix) check your configuration, **not your
running system**. Imperative changes, such as a kernel module loaded by hand
or a service started outside your configuration, are invisible to them.

**Zero untriaged is not zero vulnerabilities.**

The feed comes without warranty. You decide which risks are acceptable for
your systems. Check a statement against its sources before you rely on it for
anything that matters.

## License

This project is licensed under [MIT](./LICENSE). When you redistribute the feed
or a document derived from it, keeping its OpenVEX `author` field is attribution
enough.
