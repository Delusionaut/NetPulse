# NetPulse — local network analyzer

Desktop LAN dashboard. A Python engine discovers hosts on a background thread. A Vite + React + TypeScript UI runs in an Electron window and talks to that engine over a localhost-only HTTP API.

Scanning **always runs on a background thread**. The window stays interactive while hosts are probed. Subnets wider than /24 are capped at /24.

## Requirements

- Windows 10 or later for the installer (the engine also runs on Linux/macOS)
- Python 3.10+
- Node.js 20+ to build the UI
- Optional: [Npcap](https://npcap.com/) if you want Scapy ARP sweeps. Without it, NetPulse still discovers devices with ICMP ping plus the OS ARP table.

## Setup

```powershell
cd C:\Users\Windows\Apps\NetPulse
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd ui
npm install
```

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `NETPULSE_PORT` | `8765` | Local API port (binds to 127.0.0.1 only) |
| `NETPULSE_STATIC` | `ui/dist` if that folder exists, else none | Directory of the built React app. Set to `none` while using the Vite dev server. |
| `NETPULSE_PYTHON` | `python` | Interpreter the Electron shell uses to start the engine |

No accounts or cloud keys are required.

## Development

Terminal 1 — engine:

```powershell
cd C:\Users\Windows\Apps\NetPulse
$env:NETPULSE_STATIC = "none"
python app.py
```

Terminal 2 — UI (proxies `/api` to port 8765):

```powershell
cd C:\Users\Windows\Apps\NetPulse\ui
npm run dev
```

Open `http://127.0.0.1:5173`. A scan starts when the page loads. The page shows a short NetPulse splash, then the dashboard. Dark and light themes are both available.

To open the same UI in an Electron window against a dev engine, build once (`npm run build`) and run `npm start` from `ui`. Electron starts `python app.py` itself, so stop the other engine first or set `NETPULSE_PORT`.

## What the engine still does

The React client calls the same capabilities the old Eel page exposed:

- Background LAN scan (ICMP, ARP table, optional Scapy ARP), reverse DNS, OUI vendor and likely device nature
- TCP connect port scan (`common` or `extended`) on hosts already found on the LAN
- Live interface rates, alerts, presence history, per-device tags / trusted / owned, Wake-on-LAN
- Connectivity: ping/loss/jitter, public IP, NAT / CGNAT / double-NAT, IPv6, DNS check, traceroute, speed and bufferbloat
- Wi-Fi neighbors, this PC (NIC, listeners, processes)
- mDNS, SSDP, UPnP IGD maps, DHCP / rogue probe, DHCP fingerprints, SNMP sysName, L3 topology
- Settings stored in SQLite: schedule, webhook, JSON export
- HTTP title, TLS CN, and a risk score after a port scan
- Default-credential check only for a device you marked owned (or trusted), and only after an extra confirmation. It tries a short list of well-known HTTP basic-auth pairs. It is not a password cracker.

OUI data is cached under `cache/` for 7 days. **Refresh OUI** downloads the public IEEE and Wireshark feeds again.

## Tests

```powershell
cd C:\Users\Windows\Apps\NetPulse
python -m pytest tests -q
```

## Production build and installer

The installer is written inside this repo at `installer\`, not next to other apps.

```powershell
cd C:\Users\Windows\Apps\NetPulse\ui
npm run dist
```

That command typechecks, builds the React bundle, copies the Python modules into the package, and runs electron-builder (NSIS). The setup file is:

`C:\Users\Windows\Apps\NetPulse\installer\NetPulse-Setup-1.0.0.exe`

The installed app shows a splash (name, mark, loader), starts the Python engine, then opens the React UI. Python must be on PATH for the user who launches it (`NETPULSE_PYTHON` can point at a specific interpreter). Install the Python packages from `requirements.txt` before the first launch.

Icons used by the app and the installer live in `assets\` (`NetPulse.ico` plus PNG sizes 16, 32, 180, 192, and 512). The running app does not read `C:\Users\Windows\Apps\icons`.

## Notes

- Some hosts ignore ICMP and only show up from the ARP table.
- “Likely nature” is an inference (router, VM NIC, privacy MAC, phone, NIC vendor, IoT, and so on). IEEE registries name organizations, not exact SKUs.
- Run as Administrator when you want the most complete ARP results.
- The previous Eel window is no longer the UI. `web/index.html` remains only as the old reference page and is not packaged.
