# Deploying NetWatch

The dashboard and API are one FastAPI service. It serves the dashboard at `/`,
the optional agent installer at `/downloads/netwatch-agent`, and the API/WebSocket
on the same origin.

## Before deploying

1. Replace the shared API key in both `backend.py` and the released agent build.
   Use a unique key per deployed environment; do not publish the current key.
2. Change `BACKEND_URL` in `agent.py` to your final HTTPS address plus `/ingest`,
   rebuild the executable, then rebuild the Inno Setup installer. The supplied
   installer currently targets an old ngrok address.
3. Code-sign the Windows installer before public distribution so Windows can
   identify its publisher.
4. Set `AGENT_INSTALLER_PATH` if the installer is stored outside the default
   `dist/NetWatchSetup-v4.0.exe` location.

## Container deployment

Build and run locally:

```powershell
docker build -t netwatch .
docker run --rm -p 8000:8000 netwatch
```

Deploy the same Dockerfile to a container host such as Render, Railway, Fly.io,
Azure Container Apps, or Google Cloud Run. Configure the host health check as
`GET /status`, provide HTTPS, and set its public URL in the rebuilt agent.

## Privacy and authorization

The dashboard presents a consent screen before exposing the agent download.
Only distribute it to device owners or administrators who have authorized
monitoring. Keep a privacy notice and ensure the telemetry disclosure matches
the version of the agent you ship.
