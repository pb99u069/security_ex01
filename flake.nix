# https://www.youtube.com/watch?v=oqXWrkvZ59g
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgs = forAllSystems (system: nixpkgs.legacyPackages.${system});
      my-python-packages = ps: with ps; [
        pandas
        numpy
        pycryptodome
      ];
    in
    {
      packages = forAllSystems (system: {
        default = pkgs.${system}.poetry2nix.mkPoetryApplication { projectDir = self; };
      });

      devShells = forAllSystems (system: {
        default = pkgs.${system}.mkShellNoCC {
          shellHook = "echo Welcome to your nix powered environment";
          packages = with pkgs.${system}; [
            (poetry2nix.mkPoetryEnv { projectDir = self; })
            python310Packages.python-lsp-server
            (python3.withPackages my-python-packages)
          ];
        };
      });

      apps = forAllSystems (system: {
        default = {
          program = "${self.packages.${system}.default}/bin/start";
          type = "app";
        };
      });
    };
}
