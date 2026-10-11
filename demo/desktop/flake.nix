{
  description = "nixos-vex demo using a desktop profile";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixos-vex.url = "github:datosh/nixos-vex";
  };

  outputs =
    { nixpkgs, nixos-vex, ... }:
    {
      nixosConfigurations.desktop = nixpkgs.lib.nixosSystem {
        modules = [
          ./configuration.nix
          nixos-vex.nixosModules.default # adds system.build.vexFeed
        ];
      };
    };
}
