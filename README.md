# UniFi Security Console

A self-hosted, security-focused dashboard for UniFi networks. It connects to one or more UniFi consoles with
API keys and turns raw UniFi data into plain-English answers: what is attacking you, what your firewall really
allows, and what to fix first. It runs in Docker on your own machine; nothing is sent anywhere except calls to
your own console (and the optional, passive IP lookups you switch on).

## Features

- **Security overview** – a posture score and one ranked list of things to fix, each explained, with a
  one-click fix where the console can do it (and the steps in UniFi where it can't).
- **Threats** – every IPS/IDS detection explained: what the threat type is, which direction it went, which of
  your devices was involved, whether it was blocked, and what to do. Devices that behave like they are
  compromised are called out.
- **Investigate IP** – who an address belongs to (registry ownership and abuse contact, ASN, location, Tor exit
  status, known research scanners, optional reputation services) plus everything it did on your network.
- **Firewall & segmentation** – reads every firewall rule (zone-based or legacy), translates each into a
  sentence, and shows which network can start connections to which, to the internet and to the gateway, and
  which rule decides each path. Each path also shows what the firewall **blocked in the last 24 hours** (from
  UniFi's traffic log), and flags **near misses**: an allow rule with the wrong port or an old address.
- **Rule hygiene** – finds duplicate, redundant, shadowed, disabled and overly broad rules by comparing the
  traffic they match, not how they are written, and can remove the ones that provably do nothing.
- **Hardening** – force local DNS, isolate networks, block internet for local-only networks, lock down gateway
  management, block risky outbound services, block countries (through UniFi's own Region Blocking), IPS block
  mode, disable UPnP, guest Wi-Fi isolation, IP blocklists, port-forward fixes. Every action shows a preview,
  can turn on rule logging, and can be undone.
- **Live activity** – WAN throughput, latency, gateway load, clients per network, top talkers (5 minutes to 30
  days) and a live threat feed.
- **UniFi devices** – the gateway, switches and access points with firmware updates, ports, PoE, radios and
  who is connected; clients are identified from their MAC maker (optional offline IEEE register).
- **Multiple environments** – several consoles or sites, each with its own API key and change-safety level.
- **Change log** – every change with the exact API calls, and one-click undo.
- **Sign-in** – one account protects the dashboard; the first visit creates it.

## Requirements

- A UniFi OS console (UDM / UDR / UCG / UX / Cloud Key Gen2+) or UniFi OS Server running **UniFi Network 9.0
  or newer**. The classic self-hosted Network application (port 8443) does not support API keys.
- Docker: [Docker Desktop](https://www.docker.com/products/docker-desktop/) on Windows or macOS, or Docker
  Engine with the Compose plugin on Linux.

## Install with Docker

Pick one of the two ways below. Docker downloads the ready-made image the first time it starts, so there is
nothing to clone or build. The image runs on regular PCs and servers (amd64) and on ARM (Raspberry Pi 4/5,
Apple silicon, many NAS units).

### Option 1: docker run

```bash
docker run -d --pull always --name unifi-security-console --restart unless-stopped -p 8787:8787 -v unifi-security-console-data:/data ghcr.io/kcorr/unifi-security-console:latest
```

### Option 2: docker compose

Save this as `docker-compose.yml` in an empty folder (or download [deploy/docker-compose.yml](deploy/docker-compose.yml),
which has comments), then run `docker compose up -d` in that folder:

```yaml
services:
  unifi-security:
    image: ghcr.io/kcorr/unifi-security-console:latest
    pull_policy: always
    container_name: unifi-security-console
    restart: unless-stopped
    ports:
      - "8787:8787"
    volumes:
      - usc-data:/data

volumes:
  usc-data:
    name: unifi-security-console-data
```

Either way the dashboard is at **http://<server address>:8787**, for example <http://192.168.1.20:8787> (or
<http://localhost:8787> on the server itself). Everything is kept in the Docker volume
`unifi-security-console-data`, so you can switch between the two ways without losing anything.

**Optional settings** such as the sign-in account, `APP_SECRET` or `ALLOWED_HOSTS` go in a `.env` file (copy
[.env.example](.env.example)). Pass it with `--env-file .env` to `docker run`, or add `env_file: .env` under the
service in the compose file (the downloadable file already reads a `.env` next to it).

### First start

1. **Create your account right away.** Open the dashboard; the first visit asks for a username and a password (at
   least 12 characters), and until then nothing else is reachable. Whoever opens it first creates the account, so
   do it as soon as the container is running, or preset it with `APP_USERNAME` / `APP_PASSWORD`.
2. **Connect your console.**
   1. In UniFi Network open **Settings → Control Plane → Integrations → Create API Key** and copy the key (it is
      shown once). The key has the permissions of the admin who creates it.
   2. In the dashboard, enter the console address (for example `https://192.168.1.1`) and the key, click
      **Test connection**, then **Save & connect**. A console with several sites can be added once per site.
3. **Choose how much the console may change** (Settings → Change safety). Every environment starts **read-only**:
   you can preview every fix, but nothing is sent to UniFi until you choose otherwise.

### Updating

With docker compose, in the folder with the file:

```bash
docker compose up -d --pull always
```

With docker run, remove the container and start it again with `--pull always` (the data stays in the volume):

```bash
docker rm -f unifi-security-console
docker run -d --pull always --name unifi-security-console --restart unless-stopped -p 8787:8787 -v unifi-security-console-data:/data ghcr.io/kcorr/unifi-security-console:latest
```

To stay on one version, use one of the tags on the [package page](https://github.com/kcorr/unifi-security-console/pkgs/container/unifi-security-console) (each commit has one) instead of `latest`.

### Back up and restore your data

The volume holds your account, settings, encrypted API keys, history and the change log that undo needs.

```bash
docker stop unifi-security-console
docker run --rm -v unifi-security-console-data:/data -v "$PWD":/backup alpine tar czf /backup/usc-backup.tgz -C /data .
docker start unifi-security-console
```

To restore, stop the console and unpack the file into the volume:

```bash
docker stop unifi-security-console
docker run --rm -v unifi-security-console-data:/data -v "$PWD":/backup alpine sh -c "rm -rf /data/* && tar xzf /backup/usc-backup.tgz -C /data"
docker start unifi-security-console
```

Treat the backup like the API key itself: unless `APP_SECRET` is set, the key that decrypts your API keys is in
there too.

### Forgot your password

```bash
docker exec unifi-security-console node --disable-warning=ExperimentalWarning server/reset-login.ts
```

This removes only the sign-in account (environments, keys and history stay); the next visit creates a new one.

### Remove it

```bash
docker rm -f unifi-security-console           # or: docker compose down
docker volume rm unifi-security-console-data  # only if you also want to delete your data
```

### Access from other machines, or from this one only

The commands above publish port 8787 on all of the server's addresses, so other machines on your network can open
the dashboard by IP address (`http://192.168.1.20:8787`), by a one-word name (`http://dockerhost:8787`) or by a
local name ending in `.lan`, `.local`, `.home.arpa` or `.internal`. No setting is needed for any of these.

- **A domain name**, for example behind a reverse proxy such as Traefik or Caddy: add it to `ALLOWED_HOSTS`
  (`ALLOWED_HOSTS=usc.example.com`). Other names that look public are refused, which stops DNS rebinding: a hostile
  website pointing its own domain at your server to reach the dashboard through a visitor's browser. Use HTTPS if
  the dashboard leaves a trusted network.
- **This machine only** (a desktop rather than a server): publish the port as `127.0.0.1:8787:8787` instead.

### Build it yourself

To run your own changes, build from a clone instead of using the published image:

```bash
git clone https://github.com/kcorr/unifi-security-console.git
cd unifi-security-console
docker compose up -d --build
```

The volume is then named after the folder (for example `unifi-security-console_usc-data`); `docker volume ls`
shows it.

## Configuration

All variables are optional; `.env.example` explains each one. Pass them as described under **Optional settings** above.

| Variable | What it does |
| --- | --- |
| `APP_USERNAME`, `APP_PASSWORD` | Create the sign-in account at the first start instead of in the browser. Used once, while no account exists. |
| `APP_SECRET` | Encrypts stored API keys and signs sessions with this secret instead of a random key kept in the volume. Keep it: changing it makes stored keys unreadable. |
| `ALLOWED_HOSTS` | Domain names the dashboard answers to, comma separated, such as one behind a reverse proxy. IP addresses and local names (one word, `.lan`, `.local`, `.home.arpa`, `.internal`) always work. |
| `UNIFI_URL`, `UNIFI_API_KEY`, `UNIFI_SITE`, `UNIFI_VERIFY_TLS`, `WRITE_MODE` | Seed the first environment at the first start. If you preset a key, preset `APP_USERNAME` / `APP_PASSWORD` too, so nobody else can create the account first. |
| `THREAT_RETENTION_DAYS` | Days of threat history kept (default 30). |
| `INTEL_*`, `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY` | IP intelligence sources (see below). |

## Change safety

| Level | What the console may change |
| --- | --- |
| **Read-only** (default) | Nothing. Every plan can still be previewed with its exact API calls. |
| **Test network only** | Only new rules whose *source* is a dedicated test network named `SC-Test…`, plus creating that network (Hardening → *Create test network*). Existing rules and site settings are never touched. |
| **Full access** | Rules and settings, always after a preview. Existing rules may be extended or widened instead of duplicated. |

Every applied change is re-checked against the live object right before it is sent, recorded in the Change Log,
and can be undone.

## How hardening avoids piling up rules

Every existing rule and every proposed change is converted into the set of traffic it matches (source addresses ×
destination addresses × protocols/ports × connection states). Before anything is created, each selected network is
checked against the live rule set:

1. **Already enforced** (even by a rule written differently) → nothing is created.
2. **Partly enforced by a narrower rule** (for example it blocks UDP 53 but not TCP 53) → that rule is widened.
3. **An equivalent rule exists for other networks** → those networks are added to it.
4. Only otherwise is **one** new rule created for all remaining networks.

Intentional allow exceptions (for example a Pi-hole reaching upstream DNS) are detected and kept working; broad
allow rules that would silently override a new block are reported, and the new rule is ordered above them.

## IP intelligence is passive

- The investigated address is **never contacted**: no ping, traceroute, port scan or HTTP.
- Private and reserved addresses are classified locally and never leave the machine.
- Ownership and abuse contacts come from the responsible **regional internet registry** (RDAP), located via
  IANA's bootstrap list; requests are cached and spaced out.
- Location and ASN come from an **offline DB-IP Lite database** (CC BY 4.0), downloaded only when you click
  *Download* in Settings; afterwards every lookup is local.
- ip-api.com and Shodan InternetDB are **off by default** (third-party terms; ip-api's free tier is
  non-commercial only). AbuseIPDB and GreyNoise run only with your own API keys.
- Nothing is reported to third parties and nothing is blocked automatically.

## Security notes

- The password is stored only as a salted scrypt hash, and wrong passwords are throttled (5 per 10 minutes per
  address). Signing out ends every session; changing the password ends every other one.
- A saved API key is only ever sent to the address it was saved for; changing an environment's address asks for
  the key again.
- Consoles with a self-signed certificate are **pinned**: the app trusts the certificate it sees first (shown in
  Settings with its SHA-256 fingerprint) and refuses any other before sending a request, so the API key never
  reaches an impostor. If the console's certificate changes, Settings shows both fingerprints and lets you trust
  the new one.
- API keys are stored encrypted in the data volume. Treat the volume (and backups of it) as sensitive.
- Requests must carry an IP address, a local name or a name from `ALLOWED_HOSTS` (see above), which blocks DNS
  rebinding. Every other request needs the sign-in session (an HttpOnly, SameSite=Strict cookie), and changes also
  need a custom request header that other websites can't send.

## Which UniFi APIs are used

| Data | API |
| --- | --- |
| Networks, firewall zones & policies, traffic matching lists, Wi-Fi, devices | Official Network API (`/proxy/network/integration/v1`), Network 10.1+ |
| Zone policies on Network 9.x / 10.0 | Internal v2 API (`/v2/api/site/{site}/firewall-policies`) |
| Legacy firewall rules & groups (non-zone sites) | Internal API (`/api/s/{site}/rest/firewallrule`) |
| IPS detections | v2 traffic flows (`INTRUSION_PREVENTION`), legacy `stat/ips/event` (≤10.2), v2 system-log threat alerts |
| Blocked traffic per path | v2 traffic flows (`blocked`) |
| IPS settings, Region Blocking, UPnP, port forwards, Wi-Fi security, live stats, clients, VPN sessions | Internal API (`/api/s/{site}/...`) |

All calls use the same `X-API-KEY` header. **Settings → Diagnostics → Probe endpoints** shows which data sources
a console supports.

## Development

Requires Node.js 24+.

```bash
npm install
npm run dev:server   # API on :8787
npm run dev:web      # UI on :5173 with hot reload, proxying /api to :8787
npm test             # unit and end-to-end tests against a simulated UniFi console
npm run typecheck
```

The server runs TypeScript directly on Node 24 (type stripping), so there is no server build step. The tests use
a simulated console (`server/testing/`) that answers the same API calls as a real one; it is not part of the app
or its Docker image.

## Project layout

```
server/
  unifi/        API client, collectors, threat ingestion, pinned TLS transport
  security/     set algebra, rule normalisation, segmentation, blocked traffic, hygiene, posture,
                threat knowledge base, IP intelligence, offline geo and MAC maker databases
    hardening/  templates, planner (dedupe / extend / create, test-network guard), executor (apply / undo)
  testing/      the simulated UniFi console the tests run against
  auth.ts       sign-in account and sessions
  environments.ts  environment records (encrypted API keys)
  runtime.ts    one environment: connection, pollers, caching, live stream, change log
  service.ts    the environment registry and global settings
  index.ts      HTTP API, live stream and the web UI
shared/types.ts API contract shared with the UI
web/            React + Vite + Tailwind UI
deploy/         docker-compose.yml that runs the published image
.github/        CI: tests every push, then publishes the image to ghcr.io
```

## License

[MIT](LICENSE). UniFi is a trademark of Ubiquiti Inc.; this project is not affiliated with or endorsed by
Ubiquiti. Data the app downloads on request keeps its own license (DB-IP Lite: CC BY 4.0; the IEEE MAC
address register: IEEE's terms).
