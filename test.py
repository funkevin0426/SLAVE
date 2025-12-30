import google.generativeai as genai

genai.configure(api_key="AIzaSyCOjlEoK9hlumELyJi4xtWj5qtg1iUTj4c")

model = genai.GenerativeModel("gemini-1.5-pro")
response = model.generate_content("지구는 왜 파랗나요?")
print(response.text)