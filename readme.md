## 🛡 PHP Bot Blocker — Mini-Firewall for Shared Hosting & Simple PHP Projects

---

## 📜 Description

Most shared hosting and budget PaaS platforms (Railway, Vercel, Render, etc.) have no built-in protection against spam traffic, scanners, brute-force attempts, and cache-flooding bots.
This leads to: slower TTFB, overloaded caches, higher hosting bills, and an increased attack surface.

Bot Blocker instantly filters suspicious requests by User-Agent or path, blocks brute-force and flood attempts, and keeps a persistent ban list in SQLite for 7 days — all without root access or complex setup.
In real-world use, it cuts response times, reduces hosting costs, and keeps logs almost bot-free.

**Problem:**
This results in:

* **Increased TTFB** — sometimes by +1 second (hurts Google PageSpeed score)
* **Cache overload** — forcing CDN and app caches to store junk responses
* **Higher hosting bills** — on pay-per-use tariffs, you pay for “garbage” traffic
* **Security risks** — open attack surface for automated exploits

---

### 🛠 How This FireWall Solves the Problem

**Bot Blocker** is a **lightweight, self-contained PHP traffic filter** built for real-world **problem solving** on shared hosting and PaaS platforms:

* Instantly detects and blocks suspicious requests by **User-Agent** or **path (URI)**.
* Automatically bans an IP after **3 bad requests** or if it exceeds **10 requests in 5 seconds**.
* Stores the ban list in **SQLite** (local, no MySQL/PostgreSQL) with automatic cleanup after 7 days.
* Detects real visitor IPs behind proxy/CDN (`HTTP_X_FORWARDED_FOR`, `HTTP_CF_CONNECTING_IP`, etc.).
* Requires no root access or complex setup — integrates with **one line** in `index.php`.
* Database and logs are protected — `.db` is stored **above the web root** + `.htaccess` blocking.

---


## 🛠 Why SQLite

* 📍 **Local** — no network delays
* ⚡ **Fast** — read/write in ms
* 🔒 **Safe** — DB stored outside public webroot
* 🛠 **Zero config** — works on PHP ≥ 5.4 out of the box


---

### 🔧 Installation

1. **Place files**:

   * `bot-blocker.php` → in your PHP project root.
   * `bot-blocker.db` → stored one directory above web root for security.

2. **Protect database**: Add to `.htaccess`:

   ```apache
   <Files "bot-blocker.db">
       Order allow,deny
       Deny from all
   </Files>
   ```

3. **Include in your scripts** (e.g., at the top of `index.php`):

   ```php
   require_once __DIR__ . '/bot-blocker.php';
   ```

---

### 🚫 What It Blocks

#### Bad Paths

* WordPress attack entry points (`wp-login.php`, `xmlrpc.php`, `wp-admin`, etc.)
* Database & config files (`.env`, `.db`, `.sql`, `.zip`, `.tar`, `.gz`, `.log`, `.bak`, `.git`, `.svn`)
* Dev/project files (`composer.json`, `package.json`, `node_modules`)
* Security-related text files (`security.txt`, `.well-known/security.txt`, `ads.txt`, `humans.txt`, `llms.txt`, `list.txt`, `sitemap.xml`)

#### Bad User-Agents

* CLI tools (`curl`, `wget`, `python`, `sqlmap`, `nmap`, etc.)
* Vulnerability scanners (`acunetix`, `nikto`, `netsparker`, etc.)
* Crawlers/bots (`crawler`, `scrapy`, `search`, `spider`, etc.)
* Data mining tools (`Dataprovider`, `SimilarWeb`, `DataForSEO`, etc.)
* Performance auditing tools (`Chrome-Lighthouse`, `GTmetrix`, `WebPageTest`, etc.)
* AI crawlers/assistants (`ClaudeBot`, `ChatGPT-User`, `PerplexityBot`, etc.)


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
