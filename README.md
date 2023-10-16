Steps: 
Download Nix with $ sh <(curl -L https://nixos.org/nix/install) --no-daemon
Since flakes are an experimental feature, you also need to add the following line to ~/.config/nix/nix.conf:
experimental-features = nix-command flakes
or pass the flag --experimental-features 'nix-command flakes' whenever you call the nix command.

enter the environment with all necessary dependencies:
$ nix develop --experimental-features 'nix-command flakes'

run the program:
$ nix run
