# Cloudflare Tunnel Restore

Use this if `api.webshield.tech` stopped working after a tunnel/config file was removed.

## Goal

Route `https://api.webshield.tech` to the backend running locally on port `4000`.

## Required Files

- `cloudflared/config.yml`
- `/etc/cloudflared/webshield-api.json` (Cloudflare tunnel credentials file, not committed to git)

## Create or Update the Tunnel

If the tunnel already exists in Cloudflare, download the credentials file to the server:

```bash
sudo mkdir -p /etc/cloudflared
sudo cp /path/to/webshield-api.json /etc/cloudflared/webshield-api.json
```

If you need to create a new tunnel:

```bash
cloudflared tunnel login
cloudflared tunnel create webshield-api
cloudflared tunnel route dns webshield-api api.webshield.tech
```

## Start the Tunnel

Run the tunnel with the config in this repo:

```bash
cloudflared tunnel --config ./cloudflared/config.yml run webshield-api
```

## Verify

Check the backend health locally:

```bash
curl -i http://127.0.0.1:4000/health
```

Check the public hostname through Cloudflare:

```bash
curl -i https://api.webshield.tech/health
```

## Notes

- The tunnel should point to `http://127.0.0.1:4000`.
- If you are using nginx on the server, do not proxy `api.webshield.tech` twice. Pick either nginx or Cloudflare Tunnel.
- If the frontend uses `https://api.webshield.tech`, keep `FRONTEND_URL=https://www.webshield.tech` and make sure the backend CORS allowlist includes the frontend origin.
