{
  description = "nixos-vex: a VEX feed for NixOS, evaluated against your configuration";

  inputs = {
    # The host we scan and the tools to scan it need to move independently.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixpkgs-tools.url = "github:NixOS/nixpkgs/nixos-unstable";
    sbomnix.url = "github:tiiuae/sbomnix";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-tools,
      sbomnix,
    }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      toolsPkgs = nixpkgs-tools.legacyPackages.${system};
      tools = import ./tools {
        pkgs = toolsPkgs;
        sbomnix-upstream = sbomnix.packages.${system}.sbomnix;
      };
    in
    {
      packages.${system} = tools;

      devShells.${system} = rec {
        ci = toolsPkgs.mkShellNoCC {
          packages = [
            toolsPkgs.python3
            toolsPkgs.jq
            toolsPkgs.statix
            toolsPkgs.deadnix
            toolsPkgs.basedpyright
            toolsPkgs.ruff
            # kernel-cna-triage.py, evidence.py: GitHub compare API
            toolsPkgs.gh
          ];
        };

        default = toolsPkgs.mkShellNoCC {
          inputsFrom = [ ci ];
          packages = [
            tools.grype
            tools.sbomnix
          ];
        };
      };

      # Builds a system's VEX feed (system.build.vexFeed)
      nixosModules.default = ./modules;

      # `nix fmt`: treefmt with nixfmt over the whole tree.
      formatter.${system} = pkgs.nixfmt-tree;

      # Baseline configuration as scan target
      nixosConfigurations.baseline = nixpkgs.lib.nixosSystem {
        modules = [
          ./hosts/baseline/configuration.nix
          self.nixosModules.default
        ];
      };

      # Evaluation checks: demo personas and variants of the reference system.
      checks.${system} = import ./checks { inherit self nixpkgs pkgs; };
    };
}
