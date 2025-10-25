#!/usr/bin/env python3
"""
Access Log Generator for CTF Challenges
Generates realistic Apache/Nginx access logs with hidden malicious entries
"""

import random
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

# Common endpoints for web applications
ENDPOINTS = [
    "/wp-admin",
    "/wp-content",
    "/explore",
    "/list",
    "/app/main/posts",
    "/posts/posts/explore",
    "/search/tag/list",
    "/apps/cart.jsp?appID={}",
]

# HTTP methods and their weights
HTTP_METHODS = [
    ("GET", 70),
    ("POST", 15),
    ("PUT", 10),
    ("DELETE", 5),
]

# HTTP status codes and their weights
STATUS_CODES = [
    (200, 75),
    (301, 10),
    (404, 8),
    (500, 7),
]

# Common PHP/ASP/JSP page patterns for referrers
REFERRER_PAGES = [
    "index.php", "login.php", "register.php", "homepage.php", 
    "about.php", "search.php", "category.php", "post.php",
    "main.php", "blog.php", "terms.php", "privacy.php",
    "home.html", "index.asp", "faq.php", "author.php"
]

# User agent templates
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT {}.0) AppleWebKit/{}.{} (KHTML, like Gecko) Chrome/{}.0.{}.0 Safari/{}.{}",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{}_{}) AppleWebKit/{}.{} (KHTML, like Gecko) Chrome/{}.0.{}.0 Safari/{}.{}",
    "Mozilla/5.0 (X11; Linux x86_64; rv:1.9.{}.20) Gecko/{}-{:02d}-{:02d} {:02d}:{:02d}:{:02d} Firefox/{}.{}",
    "Mozilla/5.0 (iPhone; CPU iPhone OS {}_{}_{} like Mac OS X) AppleWebKit/{}.{} (KHTML, like Gecko) CriOS/{}.0.{}.0 Mobile/{}{}{}{}{}",
    "Mozilla/5.0 (iPad; CPU iPad OS {}_{}_{} like Mac OS X) AppleWebKit/{}.{} (KHTML, like Gecko) FxiOS/{}.{}{}{}{}{}{}{}",
    "Mozilla/5.0 (Android {}.{}.{}; Mobile; rv:{}.0) Gecko/{}.0 Firefox/{}.0",
    "Opera/9.{}.(X11; Linux x86_64; {}-{}) Presto/2.9.{} Version/{}.00",
]


def weighted_choice(choices):
    """Select from weighted choices [(item, weight), ...]"""
    total = sum(w for c, w in choices)
    r = random.uniform(0, total)
    upto = 0
    for c, w in choices:
        if upto + w >= r:
            return c
        upto += w
    return choices[-1][0]


def generate_user_agent():
    """Generate a realistic user agent string"""
    template = random.choice(USER_AGENTS)
    
    if "Windows NT" in template:
        return template.format(
            random.choice([5, 6, 10, 11]),
            random.randint(531, 537), random.randint(0, 2),
            random.randint(15, 120), random.randint(800, 900),
            random.randint(531, 537), random.randint(0, 2)
        )
    elif "Macintosh" in template:
        return template.format(
            random.randint(6, 15), random.randint(0, 9),
            random.randint(531, 537), random.randint(0, 2),
            random.randint(15, 120), random.randint(800, 900),
            random.randint(531, 537), random.randint(0, 2)
        )
    elif "X11; Linux" in template:
        return template.format(
            random.randint(5, 7),
            random.randint(2000, 9000), random.randint(1, 12), random.randint(1, 28),
            random.randint(0, 23), random.randint(0, 59), random.randint(0, 59),
            random.randint(3, 12), random.randint(0, 20)
        )
    elif "iPhone" in template:
        return template.format(
            random.randint(3, 17), random.randint(0, 7), random.randint(0, 9),
            random.randint(531, 537), random.randint(0, 2),
            random.randint(20, 60), random.randint(800, 900),
            random.randint(0, 99), chr(random.randint(65, 90)),
            random.randint(0, 9), random.randint(0, 9), random.randint(0, 9)
        )
    elif "iPad" in template:
        return template.format(
            random.randint(3, 17), random.randint(0, 7), random.randint(0, 9),
            random.randint(531, 537), random.randint(0, 2),
            random.randint(9, 18), random.randint(1, 9),
            chr(random.choice([ord('a'), ord('u'), ord('w')])),
            random.randint(0, 9), random.randint(0, 9), random.randint(0, 9), random.randint(0, 9),
            random.randint(0, 99), chr(random.randint(65, 90)), random.randint(0, 9), random.randint(0, 9)
        )
    elif "Android" in template:
        return template.format(
            random.randint(1, 14), random.randint(0, 4), random.randint(0, 9),
            random.randint(5, 67), random.randint(5, 67), random.randint(5, 67)
        )
    else:  # Opera
        lang_codes = ["en-US", "es-ES", "fr-FR", "de-DE", "ja-JP", "zh-CN"]
        return template.format(
            random.randint(10, 90),
            random.choice(lang_codes).split("-")[1], random.choice(lang_codes).split("-")[0],
            random.randint(170, 190), random.randint(10, 12)
        )


def generate_endpoint():
    """Generate a random endpoint"""
    endpoint = random.choice(ENDPOINTS)
    if "{}" in endpoint:
        return endpoint.format(random.randint(1000, 9999))
    return endpoint


def generate_referrer():
    """Generate a realistic referrer URL"""
    scheme = random.choice(["http", "https"])
    domain = fake.domain_name()
    path_parts = []
    
    # Add 0-3 path segments
    for _ in range(random.randint(0, 3)):
        path_parts.append(random.choice(["blog", "app", "category", "tag", "search", "list", "posts", "wp-content", "main", "explore", "categories", "tags"]))
    
    path = "/" + "/".join(path_parts) if path_parts else ""
    page = random.choice(REFERRER_PAGES)
    
    return f"{scheme}://{domain}{path}/{page}" if path else f"{scheme}://{domain}/{page}"


def generate_log_entry(timestamp, malicious=False, malicious_payload=None):
    """Generate a single log entry"""
    ip = fake.ipv4()
    method = weighted_choice(HTTP_METHODS)
    status = weighted_choice(STATUS_CODES)
    size = random.randint(4800, 5200)
    
    if malicious and malicious_payload:
        endpoint = malicious_payload
    else:
        endpoint = generate_endpoint()
    
    referrer = generate_referrer()
    user_agent = generate_user_agent()
    
    # Format timestamp
    time_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0500")
    
    return f'{ip} - - [{time_str}] "{method} {endpoint} HTTP/1.0" {status} {size} "{referrer}" "{user_agent}"'


def generate_logs(output_file, num_entries=100000, malicious_entries=None, random_positions=True):
    """
    Generate access logs with optional malicious entries
    
    Args:
        output_file: Path to output file
        num_entries: Total number of log entries to generate
        malicious_entries: List of dicts with malicious payloads
                          [{'position': 21494, 'payload': '...'}, ...]
                          If position is None, will place randomly
        random_positions: If True, place malicious entries at random positions
    """
    start_date = datetime(2025, 4, 12, 20, 44, 45)
    
    # Prepare malicious entry positions
    malicious_map = {}
    if malicious_entries:
        for entry in malicious_entries:
            if entry.get('position') is None and random_positions:
                # Random position
                pos = random.randint(1000, num_entries - 1000)
            else:
                pos = entry.get('position', random.randint(1000, num_entries - 1000))
            malicious_map[pos] = entry['payload']
    
    print(f"Generating {num_entries:,} log entries...")
    if malicious_map:
        print(f"Inserting {len(malicious_map)} malicious entries at positions: {sorted(malicious_map.keys())}")
    
    with open(output_file, 'w') as f:
        current_time = start_date
        
        for i in range(1, num_entries + 1):
            # Check if this should be a malicious entry
            is_malicious = i in malicious_map
            payload = malicious_map.get(i) if is_malicious else None
            
            # Generate log entry
            log_line = generate_log_entry(current_time, is_malicious, payload)
            f.write(log_line + '\n')
            
            # Increment time (random 1-300 seconds)
            current_time += timedelta(seconds=random.randint(1, 300))
            
            # Progress indicator
            if i % 10000 == 0:
                print(f"  Generated {i:,} / {num_entries:,} entries...")
    
    print(f"✓ Successfully generated {num_entries:,} log entries in: {output_file}")


if __name__ == "__main__":
    # Example: Generate logs with a hidden malicious entry
    
    malicious_payloads = [
        # {
        #     'position': 21494,  # Specific position (set to None for random)
        #     'payload': '/apps/cart.jsp?appID=7547&cmd=export%20CMD%3D%22%2Fbin%2Fsh%22%3B%20php%20-r%20%27passthru%28getenv%28%22CMD%22%29%29%3B%27'
        # },
        {
            'position': 21494,
            'payload': '"/login?username=admin%27%20OR%20%271%27=%271&password=anything'
        }
        # You can add more malicious entries:
        # {
        #     'position': None,  # Random position
        #     'payload': '/admin.php?file=../../../etc/passwd'
        # },
    ]
    
    generate_logs(
        output_file="generated_access_log.log",
        num_entries=100000,
        malicious_entries=malicious_payloads,
        random_positions=False  # Set True to randomize malicious entry positions
    )

