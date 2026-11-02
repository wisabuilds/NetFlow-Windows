# NetFlow Linux (Speed Meter, Quota & Process Attribution)

A native Linux network monitoring daemon and diagnostic engine replicating the core features of **NetworkFlow (Evozi)** and **GlassWire** on Linux.

Built entirely with standard Linux kernel interfaces (`/proc/net/dev`, `/proc/net/tcp*`, `/proc/[pid]/fd`) and Python 3 standard library with **zero third-party dependencies**.

---

## Features

* **Real-time Speed Meter**: High-precision download/upload bandwidth calculation (B/s, KB/s, MB/s) with peak rate tracking.
* **Process Attribution & Sockets (`netstat`)**: Correlates socket inodes with running PIDs and process names (`/proc/[pid]/fd`), revealing which apps are actively transmitting data.
* **Historical Time-Series (SQLite)**: Persists rolling speed metrics, daily/monthly totals, and top consuming applications.
* **Data Plan Quota & Warning Engine**: Configure monthly or daily data limits with custom warning thresholds (e.g. alert when 80% of quota is consumed).
* **Network Diagnostics**:
  * **Ping / Latency**: Continuous RTT and jitter tracking to default DNS or gateway.
  * **LAN Device Scanner**: Discovers active local subnet devices from ARP/neighbor tables with MAC OUI vendor resolution (Apple, Google, Raspberry Pi, Cisco, etc.).
  * **Speed Test**: Integrated HTTP CDN download throughput benchmark.
* **Interactive Terminal UI (TUI)**: Live terminal dashboard with ASCII sparkline graphs and top network applications.
* **REST API Server (`127.0.0.1:9095`)**: REST endpoints allowing any desktop UI (Tauri, Flutter, Qt, Web) to connect and consume real-time telemetry.

---

## Quick Start

You can use the unified `./netflow` script or `python3 main.py`:

```bash
# 1. Open the GNOME Dashboard in your browser
./netflow gui

# 2. Run the interactive Terminal UI (TUI)
./netflow tui

# 3. Run in headless daemon mode
./netflow daemon

# 4. Standalone Network Diagnostics
./netflow ping 1.1.1.1
./netflow scan
./netflow speedtest
./netflow plan 50

# 5. Linux Desktop System Integration
./netflow desktop-install   # Installs launcher to GNOME App Grid
./netflow service-install   # Installs systemd user service for auto-start
```

---

## GNOME Desktop Integration

* **Systemd User Service**: NetFlow can run continuously in the background via `systemd --user`.
* **Desktop Launcher (`.desktop`)**: Integrates directly with the GNOME Dash and Application Grid.
* **Desktop Notifications (`notify-send`)**: Automatically sends native desktop notifications when data plan quotas hit warning thresholds (e.g. 80% or 100%).

### 2. Headless Daemon (Background Service)
```bash
python3 main.py --daemon --port 9095
```

### 3. Standalone Network Tools
```bash
# Ping latency test
python3 main.py --ping 1.1.1.1

# Scan local subnet for active devices and vendor names
python3 main.py --scan

# Run internet download speed test
python3 main.py --speedtest

# Set a monthly data plan limit (e.g. 50 GB)
python3 main.py --plan-set-gb 50
```

---

## REST API Endpoints

When running, NetFlow exposes a local JSON API on port `9095`:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/stats/realtime` | `GET` | Current download/upload speed, peak rates, interfaces, and top apps |
| `/api/stats/history?seconds=60` | `GET` | Rolling time-series points for live area charts |
| `/api/stats/daily?days=30` | `GET` | Daily data consumption breakdown (Evozi style) |
| `/api/stats/top-apps?period=86400`| `GET` | Top data-consuming processes over a time window |
| `/api/netstat` | `GET` | List of all active TCP/UDP socket connections with PID & process name |
| `/api/plan` | `GET` / `POST` | Get or update data plan quotas and alert thresholds |
| `/api/diagnostics/ping` | `GET` | Measure latency to a host (`?target=8.8.8.8`) |
| `/api/diagnostics/devices` | `GET` | Discover local subnet devices and MAC vendors |
| `/api/diagnostics/speedtest` | `POST` | Run throughput benchmark (`{"size_mb": 5}`) |

---

## Running Tests

Execute the automated test suite:
```bash
python3 -m unittest discover -s tests -v
```
