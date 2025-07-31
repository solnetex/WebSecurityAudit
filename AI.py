# AI.py
import requests
import os

API_KEY = "GEMINI_API_KEY"  # API KEY, HAHA HACKER I BET U CANT SEE MY KEYYYY
ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

def summarize_security_scan(scan_data):
    headers = {
        "Content-Type": "application/json"
    }

    prompt = (
        "You are a helpful AI cybersecurity assistant. Summarize the following website scan "
        "results in a readable format. Avoid Markdown bullet points Use paragraphs or numbered lists instead. Focus on key issues, potential risks, and suggested actions:\n\n"
        + scan_data
    )

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}]
            }
        ]
    }

    response = requests.post(f"{ENDPOINT}?key={API_KEY}", headers=headers, json=payload)

    if response.status_code == 200:
        try:
            return response.json()["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            return "[Error] Could not parse the response from Gemini."
    else:
        return f"[Error] API request failed: {response.status_code} - {response.text}"


if __name__ == "__main__":
    # Sample scan data to simulate what you'd get from your tool
    test_data = """
    - TLS version: 1.0 (insecure)
    - CORS policy: Access-Control-Allow-Origin set to '*'
    - No Content-Security-Policy (CSP) header present
    - Directory listing enabled on /uploads/
    - X-Powered-By: Express (leaking technology stack)
    """

    summary = summarize_security_scan(test_data)
    print("\n--- Gemini Summary Output ---\n")
    print(summary)
