{
  description = "nixos-vex demo using a desktop profile";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # TODO: change to github:datosh/nixos-vex once the repository is public.
    nixos-vex.url = "git+ssh://git@github.com/datosh/nixos-vex";
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
