import requests

# OpenRouter API 키로 교체하세요
API_KEY = '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'
API_URL = 'https://openrouter.ai/api/v1/chat/completions'

# API 요청을 위한 헤더 정의
headers = {
    'Authorization': f'Bearer {API_KEY}',
    'Content-Type': 'application/json'
}

# 요청 페이로드(데이터) 정의
data = {
    "model": "deepseek/deepseek-chat:free",
    "messages": [{"role": "user", "content": "삶의 의미는 무엇인가요?"}]
}

# 딥시크 API에 POST 요청을 보냅니다
response = requests.post(API_URL, json=data, headers=headers)

# 요청이 성공했는지 확인
if response.status_code == 200:
    print("API 응답:", response.json())
else:
    print("API에서 데이터를 가져오지 못했습니다. 상태 코드:", response.status_code)