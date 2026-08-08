# NetWatch

NetWatch is a Windows network-monitoring demo with a FastAPI web dashboard. A
local desktop agent sends aggregate network telemetry to the dashboard, where
rule-based and ML anomaly detection are applied.

## What it collects

The Windows agent reports aggregate network metrics:

- inbound and outbound transfer rates;
- connection count and connection-rate changes;
- destination-port counts, protocol mix, and SYN rate;
- optional Snort alert text, when Snort logging is configured.

It is designed not to collect files, keystrokes, passwords, or browsing
content. Only deploy it on devices you own or are authorized to monitor.

## How it works

1. Open the landing page and download the Windows agent.
2. Install and start the visible NetWatch Agent application.
3. The agent generates a unique device ID and private dashboard token on its
   first launch.
4. Click **Copy Private Dashboard Link** in the agent, then paste that link
   into the landing page or a browser tab.
5. The private dashboard displays data only for that device.

The main landing page is `/`; the private live dashboard is `/dashboard` and
requires the device link.

## Project layout

| Path | Purpose |
| --- | --- |
| `backend.py` | FastAPI API, WebSocket stream, device pairing, and alert reports |
| `dashboard.html` | Private, live device dashboard |
| `landing.html` | Public landing page, agent download, and private-link entry |
| `agent.py` | Windows Tkinter monitoring agent |
| `ml_detector.py` | Per-device Isolation Forest baseline and quarantine logic |
| `rules.py` | Adaptive detection rules |
| `agent_config.json` | Installer configuration template — do **not** commit real secrets |
| `netwatch_setup.iss` | Inno Setup installer definition |

## Local development

Requirements: Python 3.12+.

```powershell
pip install -r requirements.txt
$env:NETWATCH_API_SECRET_KEY = "replace-with-a-strong-random-secret"
python backend.py
```

Open `http://127.0.0.1:8000`.

Before launching the agent, configure its local `agent_config.json`:

```json
{
  "backend_url": "http://127.0.0.1:8000/ingest",
  "dashboard_url": "http://127.0.0.1:8000",
  "api_secret_key": "the-same-server-secret",
  "agent_id": "auto",
  "dashboard_token": "auto"
}
```

Run the agent during development:

```powershell
python agent.py
```

## Per-device training and storage

Agents send one report every two seconds. Each device trains independently for
30 clean samples, or approximately one minute.

The server writes per-device state to:

```text
data/agents/<agent-id>/ml_baseline.pkl
data/agents/<agent-id>/quarantined_anomalies.jsonl
```

Saved dashboard alert reports are stored under:

```text
data/alert_reports/<agent-id>/
```

High and critical ML events are written to the device's quarantine file and are
excluded from subsequent baseline training.

## Build the Windows installer

Install PyInstaller and Inno Setup, then run:

```powershell
pip install pyinstaller
pyinstaller --noconfirm netwatch_agent.spec
```

Open `netwatch_setup.iss` in Inno Setup and press **F9**. The installer output
is `dist/NetWatchSetup-v4.0.exe`.

The installer preserves an existing `agent_config.json` during reinstall, so a
device keeps its same ID and private dashboard link. A fresh installation or a
deleted config file creates a new identity.

## Deploying to Render

1. Create a Render Web Service using the Docker runtime.
2. Set the health check path to `/status`.
3. Add a secret environment variable named `NETWATCH_API_SECRET_KEY`.
4. Set the same API key in the agent configuration before building the
   installer.
5. Set `backend_url` to `https://your-service.onrender.com/ingest` and
   `dashboard_url` to `https://your-service.onrender.com`.
6. Build a new installer and deploy it in `dist/`.

Render Free uses ephemeral storage. A restart or redeploy removes local models,
quarantines, alert files, and the in-memory device pairing registry. Running
agents register again automatically after a restart, but durable per-device
training requires a persistent disk (paid Render) or an external database.

## Security notes

- Private dashboard links are bearer credentials. Share them only with
  authorized viewers.
- The shared API key is suitable for development and small trusted deployments.
  Use device enrollment and per-device server-side credentials before a broader
  deployment.
- Do not commit real API keys, generated device tokens, production
  `agent_config.json`, `data/`, or packaged installers containing secrets.
- Code-sign installers before public distribution.

## License

Add a license before publishing or distributing this project.
