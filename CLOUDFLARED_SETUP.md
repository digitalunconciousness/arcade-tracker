# Cloudflare Tunnel Setup for Arcade Tracker

## 1. Overview

Cloudflare Tunnel (`cloudflared`) connects your origin server to Cloudflare's network without opening inbound ports or configuring firewall rules. Traffic arrives at Cloudflare's edge and is forwarded through an outbound connection that `cloudflared` maintains.

**Why it was set up:**
- Provides a stable, free custom domain (`tracker.greybardserver.com`) instead of a dynamic ngrok URL
- No port forwarding required on the router or Proxmox host
- The tunnel runs **alongside** the existing `arcade-tracker-ngrok.service` — both work independently

---

## 2. Prerequisites

- SSH access to the Proxmox LXC (`root@192.168.0.59` or `root@arcade-tracker`)
- A Cloudflare account with a domain added (e.g., `greybardserver.com`)
- The arcade-tracker Flask app running on port `5000`

---

## 3. Installation

SSH into the Proxmox LXC, then install `cloudflared`:

```bash
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
dpkg -i cloudflared.deb
```

---

## 4. Authentication

```bash
cloudflared tunnel login
```

This prints a URL — open it in a browser, select the domain you want to authorize, and confirm. A `cert.pem` file is saved to `~/.cloudflared/`.

---

## 5. Create the Tunnel

```bash
cloudflared tunnel create tracker
```

Note the **tunnel UUID** printed in the output. A credentials file is saved to `~/.cloudflared/<TUNNEL_UUID>.json`.

---

## 6. Configure the Tunnel

Create the config directory and file:

```bash
mkdir -p /etc/cloudflared
```

`/etc/cloudflared/config.yml`:

```yaml
tunnel: d98977c1-cc2c-43ac-8c86-86b7fd753ab1
credentials-file: /root/.cloudflared/d98977c1-cc2c-43ac-8c86-86b7fd753ab1.json

ingress:
  - hostname: tracker.greybardserver.com
    service: http://localhost:5000
  - service: http_status:404
```

---

## 7. Route DNS

If a conflicting A, AAAA, or CNAME record already exists for the hostname, delete it from the Cloudflare Dashboard first. Then:

```bash
cloudflared tunnel route dns tracker tracker.greybardserver.com
```

This creates a CNAME record pointing `tracker.greybardserver.com` → `d98977c1-cc2c-43ac-8c86-86b7fd753ab1.cfargotunnel.com`.

---

## 8. Test the Tunnel

Run the tunnel interactively to confirm it connects:

```bash
cloudflared tunnel --config /etc/cloudflared/config.yml run tracker
```

Look for `Connection registered` in the output. From another terminal:

```bash
curl tracker.greybardserver.com
```

Visit the URL in a browser to confirm the app is reachable.

---

## 9. Install as a Persistent Service

Once the tunnel is confirmed working:

```bash
cloudflared service install
systemctl enable cloudflared
systemctl start cloudflared
systemctl status cloudflared
```

The tunnel will now start automatically on boot alongside the existing `arcade-tracker-ngrok.service`.

---

## 10. Docker Compose Alternative (Optional)

To run `cloudflared` as a sidecar container instead of a host service, add this to `docker-compose.yml`:

```yaml
cloudflared:
  image: cloudflare/cloudflared:latest
  container_name: arcade-cloudflared
  restart: unless-stopped
  command: tunnel --config /etc/cloudflared/config.yml run
  volumes:
    - ./cloudflared:/etc/cloudflared
    - ./cloudflared:/root/.cloudflared
  networks:
    - arcade-net
  depends_on:
    - arcade-tracker
```

> **Note:** When using Docker networking, change `service: http://localhost:5000` in `config.yml` to `service: http://arcade-tracker:5000` so the tunnel reaches the app container by its service name.

---

## 11. Troubleshooting

### Common Errors

| Error | Cause | Fix |
|---|---|---|
| **1033** | Tunnel not running or doesn't exist | Start the tunnel daemon: `cloudflared tunnel --config /etc/cloudflared/config.yml run tracker`, or `systemctl start cloudflared` if installed as a service |
| **1003** (DNS conflict) | An A, AAAA, or CNAME record already exists for that hostname | Delete the conflicting record in the Cloudflare Dashboard, then re-run `cloudflared tunnel route dns` |
| Connection refused | Flask app not running on port 5000 | Check `systemctl status arcade-tracker` or `docker ps` |

### Useful Commands

```bash
cloudflared tunnel list                    # list all tunnels
cloudflared tunnel info tracker            # show tunnel details
systemctl status cloudflared               # check service status
journalctl -u cloudflared -f               # follow tunnel logs
systemctl restart cloudflared              # restart the tunnel
```

---

## 12. Current Setup Reference

| Setting | Value |
|---|---|
| Domain | `tracker.greybardserver.com` |
| Tunnel name | `tracker` |
| Tunnel UUID | `d98977c1-cc2c-43ac-8c86-86b7fd753ab1` |
| Config file | `/etc/cloudflared/config.yml` |
| Credentials | `/root/.cloudflared/d98977c1-cc2c-43ac-8c86-86b7fd753ab1.json` |
| Service | `systemctl status cloudflared` |
| App port | `5000` |
| Existing tunnel | `arcade-tracker-ngrok.service` (runs in parallel) |
