# Deployment

Vulnizard is one binary and one SQLite file. It listens in clear: put a reverse proxy with HTTPS in
front and set `web.base_url` to the public URL. The first import of the CVE database takes a while
and starts by itself.

**Docker**

```bash
docker compose up -d                                              # or: docker build -t vulnizard .
docker compose exec vulnizard vulnizard user create admin --admin # prompts for the password
```

The database lives in the `/data` volume; the image runs as an unprivileged user on a read-only
root. Mount your own file over `/etc/vulnizard/config.toml` to change the defaults
(`docker/container.toml`).

**NixOS** (flake)

```nix
{
  inputs.vulnizard.url = "github:likarum/Vulnizard";

  # in the modules of your host:
  imports = [ inputs.vulnizard.nixosModules.default ];
  services.vulnizard = {
    enable = true;
    baseUrl = "https://vulnizard.example.org";   # https turns on secure cookies
    # address = "127.0.0.1"; port = 8000; openFirewall = false;
    # settings.web.sync_interval_minutes = 120;  # anything from config.example.toml, no secrets
  };
}
```

The service runs hardened under a dynamic user, with its database in `/var/lib/vulnizard`.
`sudo vulnizard-admin user create admin --admin` runs any Vulnizard command on that database.
`nix build`, `nix run . -- --help` and `nix develop` work from a checkout.

## The key file

The database stores a few secrets it must be able to read back: second-factor seeds, SMTP
passwords, SSO client secrets, tokens of Git sources, webhook URLs. They are encrypted with a key
kept in a file next to the database, `<database>.key` (or the file named by `VULNIZARD_KEY_FILE`),
created at first start and readable by its owner only.

- A copy of the database alone (a backup, a dump) does not reveal these secrets.
- Someone who can read both files can: this protects copies, not a compromised server.
- **Keep the key file.** A database that holds encrypted secrets does not start without it. If
  it is lost for good, the secrets are too: second factors must be reset and passwords, client
  secrets and tokens entered again. Back it up apart from the database.

`vulnizard key path` tells where the key is and `vulnizard key export` prints it, for whoever can
already read the file on the server. It is deliberately not downloadable from the web interface.

The key can also come from a secret manager instead of being created next to the database. It is
64 hexadecimal characters (`openssl rand -hex 32`). Provide it **before the first start**, or move
the existing key into the secret.

- **NixOS**: `services.vulnizard.keyFile = config.sops.secrets."vulnizard-key".path;` (sops-nix,
  agenix or any file). The key is passed to the service as a systemd credential.
- **Docker**: mount it and name it, e.g. a second volume or a secret at `/keys`, with
  `VULNIZARD_KEY_FILE=/keys/vulnizard.key` (commented example in `docker-compose.yml`).
- **Elsewhere**: `VULNIZARD_KEY_FILE=/path/to/key`.

## Configuration

Create a `config.toml` file (optional):

```toml
# Database path (default: vulnizard.db)
db_path = "vulnizard.db"

[sync]
# Years of history to sync (default: 2)
history_years = 2

# Sources to sync (default: all)
sources = ["nvd", "cisa_kev", "epss"]

[nvd]
# NVD API key (optional, but recommended to avoid rate limiting)
# Get one at: https://nvd.nist.gov/developers/request-an-api-key
api_key = "your-api-key-here"
```

Use with: `vulnizard --config config.toml sync`

---
[← Back to the README](../README.md)
