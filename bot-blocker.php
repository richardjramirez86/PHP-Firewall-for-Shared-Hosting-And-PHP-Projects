<?php
// 🔒 Add into .htaccess:
// <Files "bot-blocker.db">
//     Order allow,deny
//     Deny from all
// </Files>

// add into index.php require_once __DIR__ . '/bot-blocker.php';

/**
* Bot Blocker + Verified Bot IP Ranges (Google & Yandex)
*
* The script performs:
* - Blocking bad User-Agents and dangerous paths
* - Limiting requests and bans by IP
* - Determining real IP behind proxy/CDN
* - Whitelisting Googlebot and YandexBot by official IP ranges
*
* IP cache in bot-blocker-ips.json (updated once a day)
*/

// ==== Settings ====
$banDurationDays = 7;
$rateLimitCount  = 10; // queries
$rateLimitTime   = 5;  // seconds
$maxAttempts     = 3;  // attempts for ban
$ipCacheFile     = __DIR__ . '/bot-blocker-ips.json';
$ipCacheTTL      = 86400; // 24 hrs

// ==== Determine the real IP ====
function getClientIP() {
    $keys = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'REMOTE_ADDR'
    ];
    foreach ($keys as $key) {
        if (!empty($_SERVER[$key])) {
            return explode(',', $_SERVER[$key])[0];
        }
    }
    return '0.0.0.0';
}

$ip = getClientIP();

// ==== IP range download and caching function ====
function loadBotIPRanges($cacheFile, $ttl) {
    $now = time();
    if (file_exists($cacheFile)) {
        $cache = json_decode(file_get_contents($cacheFile), true);
        if ($cache && ($now - $cache['time']) < $ttl) {
            return $cache['ranges'];
        }
    }

    $ranges = [];

    // Googlebot (off: https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot)
    $googleIPs = @file_get_contents('https://developers.google.com/static/search/apis/ipranges/googlebot.json');
    if ($googleIPs) {
        $json = json_decode($googleIPs, true);
        if (!empty($json['prefixes'])) {
            foreach ($json['prefixes'] as $p) {
                if (isset($p['ipv4Prefix'])) {
                    $ranges[] = $p['ipv4Prefix'];
                }
            }
        }
    }

    // Yandex (off: https://yandex.com/support/webmaster/robot-workings/check-yandex-robots.html)
    $yandexIPs = @file_get_contents('https://yandex.com/support/webmaster/robot-workings/ips.xml');
    if ($yandexIPs && preg_match_all('/<ip>([^<]+)<\/ip>/', $yandexIPs, $m)) {
        $ranges = array_merge($ranges, $m[1]);
    }

    file_put_contents($cacheFile, json_encode(['time' => $now, 'ranges' => $ranges], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    return $ranges;
}

$botIPRanges = loadBotIPRanges($ipCacheFile, $ipCacheTTL);

// ==== Check if IP belongs to Google/Yandex bots ====
function ipInRanges($ip, $ranges) {
    foreach ($ranges as $range) {
        if (strpos($range, '/') !== false) {
            if (ipInCidr($ip, $range)) return true;
        } elseif ($ip === $range) {
            return true;
        }
    }
    return false;
}

function ipInCidr($ip, $cidr) {
    list($subnet, $mask) = explode('/', $cidr);
    return (ip2long($ip) & ~((1 << (32 - $mask)) - 1)) === ip2long($subnet);
}

// ==== If it's Googlebot or YandexBot by IP — skip ====
if (ipInRanges($ip, $botIPRanges)) {
    return;
}

// ==== Checking User-Agent ====
$ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$badUAs = [
    'curl', 'wget', 'python', 'sqlmap', 'nmap', 'nikto', 'acunetix', 'netsparker',
    'dataprovider', 'lighthouse', 'claudebot', 'chatgpt', 'scrapy', 'crawler', 'spider'
];
foreach ($badUAs as $bad) {
    if (strpos($ua, $bad) !== false) {
        header('HTTP/1.1 403 Forbidden');
        exit;
    }
}


$basePath = __DIR__;
$dbPath = realpath($basePath . '/../') . '/bot-blocker.db';

// 📡 Determine the real IP
$ip = getRealIp();
$userAgent = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$uri = $_SERVER['REQUEST_URI'] ?? '/';

// 🚫 Dangerous Paths and Extensions
$badPaths = [
    'wp-login.php', 'wp-admin', 'xmlrpc.php', 'wp-content',
    'phpmyadmin', 'setup.php', 'core/', 'config.core.php',
    'connectors/', '.env', '.db', '.sql', '.zip', '.tar',
    '.gz', '.log', '.bak', '.git', '.svn', '.htaccess',
    '.htpasswd', 'vendor/', 'composer.json', 'composer.lock',
    'node_modules', 'package.json', 'package-lock.json',
    'readme.md', 'readme.txt', 'license', 'changelog',
    'backup', 'adminer.php', 'shell.php', 'cmd.php',
    'info.php', 'test.php', 'phpinfo', 'pma/', 'mysql/',
    'dump.sql', 'database.sql',
    'security.txt', '.well-known/security.txt',
    'ads.txt', 'humans.txt', 'llms.txt', 'list.txt', 'sitemap.xml'
];

// 🕷️ Bad User-Agent
$badAgents = [
    'curl', 'python', 'wget', 'sqlmap', 'nmap',
    'libwww', 'masscan', 'nikto', 'scan',
    'fuzzer', 'acunetix', 'netsparker', 'jaeles',
    'httpclient', 'dirbuster', 'w3af', 'paros',
    'arachni', 'havij', 'zmeu', 'binlar',
    'nessus', 'httperf', 'winhttp', 'libwww-perl',
    'feedfetcher', 'crawler', 'scrapy', 'search', 'spider',
    'openvas', 'sqlninja', 'brutus', 'hydra',
    'dataprovider', 'chrome-lighthouse', 'claudebot', 'chatgpt-user'
];

// 🛡️ Connecting to SQLite
$db = new SQLite3($dbPath);
$db->exec("CREATE TABLE IF NOT EXISTS bans (
    ip TEXT PRIMARY KEY,
    attempts INTEGER DEFAULT 1,
    last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP
)");
$db->exec("CREATE TABLE IF NOT EXISTS requests (
    ip TEXT,
    ts INTEGER
)");

// 🧹 Cleaning up old records
$db->exec("DELETE FROM bans WHERE last_attempt < datetime('now', '-7 days')");
$db->exec("DELETE FROM requests WHERE ts < " . (time() - 60));

// 🔒 Checking whether the IP is banned
$stmt = $db->prepare("SELECT ip FROM bans WHERE ip = :ip");
$stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
$res = $stmt->execute();
if ($res->fetchArray()) {
    blockAndExit();
}

// 🧨 Check by URI
foreach ($badPaths as $path) {
    if (stripos($uri, $path) !== false ||
        preg_match('#\.(env|db|sql|zip|tar|gz|log|bak|git|svn|htaccess|htpasswd|txt)$#i', $uri)
    ) {
        autoBan($ip, $db);
        blockAndExit();
    }
}

// 🐍 Check by User-Agent
foreach ($badAgents as $bot) {
    if (strpos($userAgent, $bot) !== false) {
        autoBan($ip, $db);
        blockAndExit();
    }
}

// 📈 Request limit
logRequest($ip, $db);
if (tooManyRequests($ip, $db, 10, 5)) { // >10 за 5 секунд
    autoBan($ip, $db);
    blockAndExit();
}

// 📌 Getting a real IP
function getRealIp() {
    $keys = [
        'HTTP_CF_CONNECTING_IP', // Cloudflare
        'HTTP_X_REAL_IP',        // Nginx proxy / some CDN
        'HTTP_X_FORWARDED_FOR',  // general proxy
        'REMOTE_ADDR'
    ];
    foreach ($keys as $key) {
        if (!empty($_SERVER[$key])) {
            // Если в заголовке несколько IP — берём первый
            $ipList = explode(',', $_SERVER[$key]);
            $ip = trim($ipList[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return 'unknown';
}

// ⚙️ Automatic ban
function autoBan($ip, $db, $limit = 3) {
    $stmt = $db->prepare("SELECT attempts FROM bans WHERE ip = :ip");
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $res = $stmt->execute();
    $row = $res->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        $attempts = $row['attempts'] + 1;
        $stmt = $db->prepare("UPDATE bans SET attempts = :attempts, last_attempt = CURRENT_TIMESTAMP WHERE ip = :ip");
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $stmt->bindValue(':attempts', $attempts, SQLITE3_INTEGER);
        $stmt->execute();
    } else {
        $stmt = $db->prepare("INSERT INTO bans (ip) VALUES (:ip)");
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $stmt->execute();
    }
}

// 📝 Logging the request
function logRequest($ip, $db) {
    $time = time();
    $stmt = $db->prepare("INSERT INTO requests (ip, ts) VALUES (:ip, :ts)");
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $stmt->bindValue(':ts', $time, SQLITE3_INTEGER);
    $stmt->execute();
}

// 📊 Checking the request limit
function tooManyRequests($ip, $db, $limit, $seconds) {
    $time = time();
    $stmt = $db->prepare("SELECT COUNT(*) AS cnt FROM requests WHERE ip = :ip AND ts > :t");
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $stmt->bindValue(':t', $time - $seconds, SQLITE3_INTEGER);
    $res = $stmt->execute();
    $row = $res->fetchArray(SQLITE3_ASSOC);
    return $row['cnt'] > $limit;
}

// ⛔ Output and exit
function blockAndExit() {
    header('HTTP/1.1 403 Forbidden');
    exit("site in progres.");
}
