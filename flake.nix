{
  description = "Vulnizard — self-hosted vulnerability monitoring (one binary, one SQLite file)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      cargo = (nixpkgs.lib.importTOML ./Cargo.toml).package;
    in
    {
      packages = forAllSystems (pkgs: rec {
        vulnizard = pkgs.rustPlatform.buildRustPackage {
          pname = cargo.name;
          inherit (cargo) version;
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./src ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          # nixpkgs makes the zstd (pulled by zip) and SQLite crates link the system libraries
          buildInputs = [ pkgs.openssl pkgs.zstd pkgs.sqlite ];
          # The test suite resolves names and opens sockets, which the build sandbox forbids
          doCheck = false;
          meta = {
            inherit (cargo) description;
            license = pkgs.lib.licenses.mit;
            mainProgram = "vulnizard";
          };
        };
        default = vulnizard;
      });

      overlays.default = final: _prev: { vulnizard = self.packages.${final.stdenv.hostPlatform.system}.vulnizard; };

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.vulnizard ];
          packages = [ pkgs.cargo pkgs.rustc pkgs.clippy pkgs.rustfmt pkgs.rust-analyzer ];
        };
      });

      # services.vulnizard.enable = true;
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.vulnizard;
          toml = pkgs.formats.toml { };
          configFile = toml.generate "vulnizard.toml" (lib.recursiveUpdate
            {
              db_path = "/var/lib/vulnizard/vulnizard.db";
              web = {
                bind = "${cfg.address}:${toString cfg.port}";
                base_url = cfg.baseUrl;
                secure_cookies = lib.hasPrefix "https://" cfg.baseUrl;
              };
            }
            cfg.settings);
        in
        {
          options.services.vulnizard = {
            enable = lib.mkEnableOption "the Vulnizard vulnerability monitoring server";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.vulnizard;
              description = "Vulnizard package to run.";
            };
            address = lib.mkOption {
              type = lib.types.str;
              default = "127.0.0.1";
              description = "Listen address. Keep loopback and put a reverse proxy with HTTPS in front.";
            };
            port = lib.mkOption {
              type = lib.types.port;
              default = 8000;
              description = "Listen port.";
            };
            baseUrl = lib.mkOption {
              type = lib.types.str;
              default = "http://127.0.0.1:${toString cfg.port}";
              example = "https://vulnizard.example.org";
              description = "Public URL (links in notifications, SSO redirect URIs). An https URL turns on secure cookies.";
            };
            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Open the listen port in the firewall.";
            };
            settings = lib.mkOption {
              inherit (toml) type;
              default = { };
              example = { web.sync_interval_minutes = 120; sync.sources = [ "nvd" "cisa_kev" "epss" ]; };
              description = ''
                Extra settings merged into the configuration file (see config.example.toml).
                This file ends up in the world-readable Nix store: do not put secrets here.
                The NVD API key, SMTP servers and SSO providers are set in the Admin pages,
                which store them in the database.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            # `vulnizard user create admin --admin` and other commands, on the same database
            environment.systemPackages = [
              (pkgs.writeShellScriptBin "vulnizard-admin" ''
                exec ${pkgs.systemd}/bin/systemd-run --quiet --pty --wait --collect \
                  --property=DynamicUser=yes --property=User=vulnizard \
                  --property=StateDirectory=vulnizard --working-directory=/var/lib/vulnizard \
                  ${lib.getExe cfg.package} --config ${configFile} "$@"
              '')
            ];

            networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

            systemd.services.vulnizard = {
              description = "Vulnizard vulnerability monitoring";
              wantedBy = [ "multi-user.target" ];
              wants = [ "network-online.target" ];
              after = [ "network-online.target" ];
              serviceConfig = {
                ExecStart = "${lib.getExe cfg.package} --config ${configFile} serve";
                Restart = "on-failure";
                DynamicUser = true;
                User = "vulnizard";
                StateDirectory = "vulnizard";
                StateDirectoryMode = "0700";
                WorkingDirectory = "/var/lib/vulnizard";
                # Hardening
                CapabilityBoundingSet = "";
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                NoNewPrivileges = true;
                PrivateDevices = true;
                PrivateTmp = true;
                ProtectClock = true;
                ProtectControlGroups = true;
                ProtectHome = true;
                ProtectHostname = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
                ProtectKernelTunables = true;
                ProtectProc = "invisible";
                ProtectSystem = "strict";
                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
                RestrictNamespaces = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                SystemCallArchitectures = "native";
                SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
                UMask = "0077";
              };
            };
          };
        };
    };
}
