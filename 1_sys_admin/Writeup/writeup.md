# EASY - sys_admin writeup

## Challenge Description
Someone tried to exploit the server through a web attack. We need to analyze access logs to find the malicious request and identify the attacker.

**Flag Format**: `flag{IP:Timestamp}` where timestamp is in the format `[DD/MMM/YYYY:HH:MM:SS +XXXX]`

## Solution

#### Method 1: Search for URL-encoded characters
```bash
grep '%27' access_logs_12-4-25_03_10_25.log
```

This searches for `%27` which is the URL-encoded single quote (`'`) commonly used in SQL injection attacks.

#### Method 2: Search for SQL injection patterns
```bash
grep -i "OR.*1.*=.*1" access_logs_12-4-25_03_10_25.log
```

This searches for the classic SQL injection pattern `OR '1'='1'`.

#### Method 3: Search for authentication bypass attempts
```bash
grep -E "username=.*%27|password=.*%27" access_logs_12-4-25_03_10_25.log
```

This searches for single quotes in username or password parameters.

Whatever way you choose, this is the line that you end up finding, as you can see, it is a standard sql injection attack

```
135.90.188.169 - - [20/May/2025:05:30:05 +0500] "GET "/login?username=admin%27%20OR%20%271%27=%271&password=anything HTTP/1.0" 200 5090 "https://black.info/app/tag/tag/faq.php" "Mozilla/5.0 (Windows NT 5.0) AppleWebKit/534.1 (KHTML, like Gecko) Chrome/73.0.858.0 Safari/535.0"
```

```
/login?username=admin' OR '1'='1&password=anything
```

From the malicious log entry:
- **Attacker IP Address**: `135.90.188.169`
- **Attack Timestamp**: `[20/May/2025:05:30:05 +0500]`

## Flag

```
flag{135.90.188.169:[20/May/2025:05:30:05 +0500]}
```