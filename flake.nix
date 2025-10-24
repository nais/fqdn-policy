{
  description = "FQDN Policy";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs =
    inputs:
    let
      goOverlay =
        final: prev:
        let
          goVersion = "1.24.4";
          newerGoVersion = prev.go.overrideAttrs (old: {
            inherit goVersion;
            src = prev.fetchurl {
              url = "https://go.dev/dl/go${goVersion}.src.tar.gz";
              hash = "sha256-WoaoOjH5+oFJC4xUIKw4T9PZWj5x+6Zlx7P5XR3+8rQ=";
            };
          });
          nixpkgsVersion = prev.go.version;
          newVersionNotInNixpkgs = -1 == builtins.compareVersions nixpkgsVersion goVersion;
        in
        {
          go = if newVersionNotInNixpkgs then newerGoVersion else prev.go;
          buildGoModule = prev.buildGoModule.override { go = final.go; };
        };
      withSystem = inputs.nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      withPkgs =
        callback:
        withSystem (
          system:
          callback (
            import inputs.nixpkgs {
              inherit system;
              overlays = [ goOverlay ];
            }
          )
        );
    in
    {
      devShells = withPkgs (pkgs: let
        inherit (pkgs) lib;
       in {
        default = pkgs.mkShell {
          KUSTOMIZE = lib.getExe' pkgs.kubernetes-controller-tools "kustomize";
          CONTROLLER_GEN = lib.getExe' pkgs.kubernetes-controller-tools "controller-gen";
          ENVTEST = lib.getExe' pkgs.kubernetes-controller-tools "setup-envtest";
          packages = with pkgs; [
            go
            gopls
            gotools
            go-tools
            gofumpt
            kubernetes-controller-tools
          ];
        };
      });
      formatter = withPkgs (pkgs: pkgs.nixfmt-rfc-style);
    };
}
