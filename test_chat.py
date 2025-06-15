import google.generativeai as genai

genai.configure(api_key="AIzaSyARl5KvLixsra654jbox6IqgELoCOWthDE")

response = genai.chat.completions.create(
    model="gemini-flash-1",
    messages=[{"role": "system", "content": "Say hello"}, {"role": "user", "content": "Hello"}],
)

print(response.choices[0].message.content)
