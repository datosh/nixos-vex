{ pkgs, sbomnix-upstream }:
let
  inherit (builtins.fromJSON (builtins.readFile ./pins.json)) grypeDb cpedictRev;
in
rec {
  # The vulnerability DB, imported into the layout of a grype DB cache dir.
  grype-db =
    pkgs.runCommand grypeDb.name
      {
        archive = pkgs.fetchurl {
          inherit (grypeDb) url hash;
          name = "${grypeDb.name}.tar.zst";
        };
        nativeBuildInputs = [ pkgs.grype ];
      }
      ''
        GRYPE_DB_CACHE_DIR=$out grype -v db import "$archive"
        test -s $out/6/vulnerability.db
      '';

  grype =
    let
      config = pkgs.writeText "grype.yaml" (
        builtins.toJSON {
          check-for-app-update = false;
          db = {
            cache-dir = "${grype-db}";
            auto-update = false;
            validate-age = false;
          };
        }
      );
    in
    pkgs.writeShellApplication {
      name = "grype";
      runtimeInputs = [ pkgs.grype ];
      text = ''
        for var in "''${!GRYPE_@}"; do unset "$var"; done
        exec grype --config ${config} "$@"
      '';
    };

  # vexctl with `validate` (lints OpenVEX documents, `make lint`), which no
  # release has yet. Updated by hand, not by `make bump`: set rev, then fix
  # the version date, src hash and vendorHash from the build errors.
  # TODO: use pkgs.vexctl once nixpkgs ships vexctl 0.5.0 (the first release
  # with `validate`), and drop this override.
  # vexctl main needs Go >= 1.27.1.
  vexctl = (pkgs.vexctl.override { buildGoModule = pkgs.buildGo127Module; }).overrideAttrs (
    finalAttrs: _: {
      version = "0.4.4-unstable-2026-10-06";
      src = pkgs.fetchFromGitHub {
        owner = "openvex";
        repo = "vexctl";
        rev = "e0849bfe121e60a7caca230cd195895ac4b4b813";
        hash = "sha256-a52viakqClRSRitw3/LRitU7e7spATRWEQ4BnruAW4s=";
      };
      vendorHash = "sha256-ldROpsLj/0dI+3Kd8AYCiQQavbWUpL3Vdfm/JvVv1MU=";
      # `add` dates statements from SOURCE_DATE_EPOCH, which the Nix build sets
      # to 1980, before the test document's timestamp.
      checkFlags = [ "-skip=^TestAddNoProductFlag$" ];
      # nixpkgs reads the commit from a file its fetcher writes.
      preBuild = ''
        ldflags+=" -X sigs.k8s.io/release-utils/version.gitCommit=${finalAttrs.src.rev}"
      '';
    }
  );

  sbomnix = sbomnix-upstream.overridePythonAttrs (old: {
    # Pin the version of the CPE database used.
    # TODO: Report upstream to add proper support
    postPatch = old.postPatch + ''
      printf '%s' ".cpedict.${builtins.substring 0 7 cpedictRev}" >> VERSION
      substituteInPlace src/sbomnix/cpe.py --replace-fail \
        '"https://github.com/tiiuae/cpedict/raw/main/data/cpes.csv"' \
        '"https://raw.githubusercontent.com/tiiuae/cpedict/${cpedictRev}/data/cpes.csv"'
    '';
    version = "${old.version}.cpedict.${builtins.substring 0 7 cpedictRev}";
  });
}
