How to use nix to manage the dependencies of the program:

Download nix:
```bash
$ curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```
From the root folder containing the flake.nix, enter the environment with the required dependencies:
```bash
$ nix develop
```
Run the program:
```bash
$ nix run
```
