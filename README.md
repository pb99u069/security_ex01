Steps: 

Download nix with:

$ curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install

Enter the environment with dependencies with:

$ nix develop

Run the program:

$ nix run
