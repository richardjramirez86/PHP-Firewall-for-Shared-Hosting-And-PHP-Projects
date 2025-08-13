# 🛡 PHP Bot Blocker — Firewall for Shared Hosting & PHP Projects

---

## 📜 Description

**PHP Bot Blocker** is a **lightweight, self-contained firewall** for PHP projects that protects against spam traffic, vulnerability scanners, brute-force attacks, and cache-flooding bots — **without root access or complex setup**.  

Designed for **shared hosting** and **pay-as-you-go cloud platforms** (Railway, Vercel, Render, etc.), it filters malicious requests instantly, blocks suspicious IPs, and keeps a **persistent ban list** in SQLite for 7 days.  

✅ Works on PHP ≥ 5.4  
✅ No server modules or external APIs required  
✅ Protects both static and dynamic PHP sites  

---

## 🚨 The Problem

| ❌ Problem | 💥 Impact |
|-----------|----------|
| Bots and scanners flood your site with junk requests | Higher TTFB, lower PageSpeed score |
| Sensitive files and CMS admin pages exposed | Risk of exploits and data leaks |
| CDN and app cache filled with garbage | Wasted bandwidth and storage |
| High request rates from one IP | Potential DDoS or service slowdown |
| Pay-as-you-go hosting bills inflated | Paying for “garbage” traffic |

---

## 🛠 How This Firewall Solves It

| ✅ Feature | 🚀 Benefit |
|-----------|-----------|
| Blocks bad User-Agents (scanners, scrapers, AI crawlers) | Cuts junk traffic instantly |
| Denies access to dangerous paths/files (`wp-login.php`, `.env`, `.sql`, `.git`, etc.) | Prevents common exploit entry points |
| Auto-bans IPs after 3 bad requests | Stops brute-force attempts |
| Rate limiting — 10+ requests in 5 sec → ban | Mitigates flood attacks |
| Persistent bans in SQLite (7 days) | Survives restarts without MySQL |
| Automatic cleanup of old logs | Keeps DB small & fast |
| Detects real IP behind Cloudflare/proxies | Avoids false bans |

---

## 📌 Why SQLite

| 📍 Local | ⚡ Fast | 🔒 Secure | 🛠 Zero Config |
|----------|--------|-----------|---------------|
| No network latency | Read/write in milliseconds | Stored outside public webroot | Works out-of-the-box on PHP ≥ 5.4 |

---

## ⚙️ Installation

1. **Place files**:  
   - `bot-blocker.php` → project root  
   - `bot-blocker.db` → **one directory above web root**  

2. **Protect the database** — add to `.htaccess`:  
   ```apache
   <Files "bot-blocker.db">
       Order allow,deny
       Deny from all
   </Files>

3. **Include in your PHP scripts** (e.g., in `index.php`):

   ```php
   require_once __DIR__ . '/bot-blocker.php';
   ```

---

## 🚫 What It Blocks

### Bad Paths

* WordPress entry points (`wp-login.php`, `xmlrpc.php`, `wp-admin`)
* Config/DB files (`.env`, `.sql`, `.db`, `.git`, `.svn`, `.bak`)
* Dev files (`composer.json`, `package.json`, `node_modules`)
* Spam `.txt` files (`ads.txt`, `humans.txt`, `security.txt`, `sitemap.xml`)

### Bad User-Agents

* CLI tools (`curl`, `wget`, `python`, `sqlmap`, `nmap`)
* Vulnerability scanners (`acunetix`, `nikto`, `netsparker`)
* Crawlers/bots (`crawler`, `scrapy`, `search`, `spider`)
* Data miners (`Dataprovider`, `SimilarWeb`, `DataForSEO`)
* Performance tools (`Chrome-Lighthouse`, `GTmetrix`, `WebPageTest`)
* AI crawlers (`ClaudeBot`, `ChatGPT-User`, `PerplexityBot`)

---

## 📌 Problem → Solution

| Problem                                                                      | How Bot Blocker Solves It                                                                                                                                                             |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Junk requests from bad User-Agents** (bots, scrapers, scanners)            | Detects and blocks instantly by matching against an extended bad UA list (including Dataprovider, Chrome-Lighthouse, ClaudeBot, ChatGPT, vulnerability scanners, CLI tools).          |
| **Access to sensitive files** (`wp-login.php`, `.env`, `.sql`, `.git`, etc.) | Blocks requests to known dangerous paths and files, including CMS admin pages, config files, backups, and spam `.txt` files (`ads.txt`, `humans.txt`, `security.txt`, `sitemap.xml`). |
| **Brute-force & vulnerability scanning**                                     | Tracks repeated suspicious requests from the same IP and bans offenders after a set number of attempts (default: 3).                                                                  |
| **Flood / rate-based attacks**                                               | Implements rate limiting: more than 10 requests in 5 seconds from one IP → instant ban.                                                                                               |
| **Temporary bans that reset on restart**                                     | Stores bans in a local SQLite database for 7 days — persistent across server restarts.                                                                                                |
| **Database overload with request logs**                                      | Automatic cleanup of old request logs every minute to keep storage small and performance high.                                                                                        |
| **Wrong IP bans behind proxy/CDN**                                           | Detects real visitor IP from Cloudflare and proxy headers (`HTTP_X_FORWARDED_FOR`, `HTTP_CF_CONNECTING_IP`, etc.), not just `REMOTE_ADDR`.                                            |

---
