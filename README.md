Use nix to manage the dependencies of the program:

Download nix with
```bash
$ curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```
Enter the environment containing the required dependencies with
```bash
$ nix develop
```
Run the program
```bash
$ nix run
```
