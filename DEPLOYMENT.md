# 🚀 AWS EC2 Deployment Guide — Vuln Spectra Backend

This guide details how to deploy the **Vuln Spectra** backend to an Ubuntu-based AWS EC2 instance.

## 1. System Requirements & Dependencies
Login to your EC2 instance via SSH and run the following commands to install Node.js and the required security tools.

### Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### Install Node.js (v18+)
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

### Install Security Tools (Required for Scans)
```bash
sudo apt install -y nmap nikto sslscan sqlmap build-essential
```

### Install PM2 (Global)
```bash
sudo npm install -g pm2
```

---

## 2. Setup the Repository
Clone your backend repository (replace with your actual repo URL):

```bash
git clone <YOUR_BACKEND_REPO_URL>
cd <REPO_DIRECTORY>
npm install
```

---

## 3. Environment Configuration
Create the `.env` file manually:

```bash
nano .env
```

Paste and configure the following variables:
```env
PORT=4000
DB_URL=mongodb+srv://... (your MongoDB URI)
JWT_SECRET=... (a random long string)
GROQ_API=... (your Groq API key)
FRONTEND_URL=https://your-frontend.vercel.app

# Email settings (for password resets)
EMAIL_USER=...
EMAIL_PASS=...

# Optional: enable only if backend runs with required nmap privileges
# (root user or proper Linux capabilities)
NMAP_ENABLE_OS_DETECTION=false
```
*Press `Ctrl+O`, `Enter`, then `Ctrl+X` to save and exit.*

If you enable `NMAP_ENABLE_OS_DETECTION=true` on a non-root PM2 process, grant Nmap capabilities once:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v nmap)"
```

---

## 4. Launch with PM2
Launch the application using the pre-configured `ecosystem.config.json`:

```bash
pm2 start ecosystem.config.json
```

### Useful PM2 Commands:
- **View Logs**: `pm2 logs vuln-spectra-backend`
- **Check Status**: `pm2 list`
- **Restart**: `pm2 restart vuln-spectra-backend`
- **Stop**: `pm2 stop vuln-spectra-backend`

---

## 5. Expose the Port (AWS Security Groups)
1. Go to your **AWS Console** > **EC2 Instances**.
2. Select your instance > **Security** tab > Click the **Security Group**.
3. Edit **Inbound Rules**.
4. Add a rule: 
   - **Type**: Custom TCP
   - **Port Range**: `4000`
   - **Source**: `Anywhere (0.0.0.0/0)` or your specific frontend IP.

---

## 6. (Optional) Nginx Reverse Proxy
If you want to use a domain name (e.g., `api.vulnspectra.com`) or SSL (HTTPS):
1. Install Nginx: `sudo apt install nginx`
2. Configure a server block to proxy port `80` to `localhost:4000`.
3. Use **Certbot** for free SSL: `sudo apt install certbot python3-certbot-nginx && sudo certbot --nginx`

---

**✅ Your backend is now live!** Update your Vercel `VITE_API_URL` to point to your EC2 public IP or domain (e.g., `http://3.x.x.x:4000`).
