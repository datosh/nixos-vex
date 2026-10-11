{ ... }:

{
  imports = [ ./hardware-configuration.nix ];

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  networking = {
    hostName = "server";
    # systemd-networkd does DHCP instead of dhcpcd, the default with useDHCP.
    useNetworkd = true;
    firewall.enable = true;
  };

  # Key-only login: no passwords, no keyboard-interactive (PAM challenge-response).
  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "no";
    };
  };

  users.users.admin = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoKeyReplaceWithYourOwnPublicKeyxxxxxx admin@example"
    ];
  };

  system.stateVersion = "26.11";
}
