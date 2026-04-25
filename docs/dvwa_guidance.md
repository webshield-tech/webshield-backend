# DVWA Testing Guide for WebShield (Vuln Spectra)

This guide provides instructions on how to use Damn Vulnerable Web App (DVWA) to safely test the WebShield scanning engine locally.

## Why DVWA?
DVWA is a deliberately vulnerable web application designed for security professionals to test their skills and tools in a legal environment. Testing Vuln Spectra against DVWA ensures that the scanner correctly identifies common vulnerabilities like SQL Injection, Cross-Site Scripting (XSS), and Command Injection.

## Prerequisites
- Docker & Docker Compose installed
- WebShield backend running locally
- Vuln Spectra platform accessible via `http://localhost:3000`

## 1. Starting DVWA
The easiest way to run DVWA is using Docker:
```bash
docker run --rm -it -p 8080:80 vulnerables/web-dvwa
```
This will start DVWA on port `8080`.
You can access it at `http://localhost:8080` (or `http://127.0.0.1:8080`).

## 2. DVWA Setup
1. Open your browser and navigate to `http://localhost:8080/setup.php`
2. Click **"Create / Reset Database"** at the bottom of the page.
3. Login using the default credentials:
   - **Username:** `admin`
   - **Password:** `password`
4. Go to the **DVWA Security** tab and set the Security Level to `Low` for testing.

## 3. Testing Scanners
When running scans in Vuln Spectra, target the DVWA instance at `http://localhost:8080` (or `http://127.0.0.1:8080`).

- **Nmap**: Will discover open port 8080 and fingerprint the underlying Apache/PHP stack.
- **Nikto**: Will detect outdated software versions, vulnerable headers, and test for basic vulnerabilities like XSS.
- **SQLMap**: To effectively test SQLMap, you will need to scan a specific vulnerable parameter in DVWA (e.g., the SQL Injection page), passing the session cookie if required.

## 4. PoC (Proof of Concept) Simulation
When Vuln Spectra identifies a vulnerability in DVWA (such as SQLi or XSS), you can trigger the **Auto Proof of Concept (PoC)** feature. 
Since DVWA is hosted on localhost, the WebShield engine will allow the PoC simulation, safely executing the payload and returning an AI-generated explanation of the exploit, its impact, and mitigation.

> [!WARNING]
> Ensure you only run PoC simulations on `localhost` or `127.0.0.1` as enforced by the WebShield backend.

## 5. Cleaning Up
Stop the Docker container once testing is complete:
```bash
docker ps
docker stop <container_id>
```
