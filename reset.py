import os
from app import db, app

db_path = 'posts.db'

# 기존 DB 파일 삭제
if os.path.exists(db_path):
    os.remove(db_path)
    print(f"{db_path} 삭제 완료")
else:
    print(f"{db_path} 파일이 존재하지 않습니다.")

# 새로운 DB 생성
with app.app_context():
    db.create_all()
    print("새 데이터베이스 생성 완료")
