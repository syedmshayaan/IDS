import requests

SANDBOX_URL = "http://16.171.148.252:5001/analyze"
API_KEY     = "ids-secret-key"

def send_to_sandbox(payload: str) -> dict:
    try:
        response = requests.post(
            SANDBOX_URL,
            json    = {"payload": payload},
            headers = {"X-API-Key": API_KEY},
            timeout = 15
        )
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"verdict": "unreachable", "detail": str(e)}

if __name__ == "__main__":
    test_cases = [
        "print(1+1)",
        "import os; os.system('whoami')",
    ]
    for payload in test_cases:
        result = send_to_sandbox(payload)
        print(f"Payload: {payload[:40]}")
        print(f"Verdict: {result['verdict']}\n")
