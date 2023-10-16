Steps: 

Download nix with:
```bash
$ curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```
Enter the environment with dependencies with:
```bash
$ nix develop
```
Run the program:
```bash
$ nix run
```
