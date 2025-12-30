from app import db, Post, app  # app.py에서 db와 Post 모델, app 객체를 가져옵니다.

def create_test_posts():
    with app.app_context():  # 애플리케이션 컨텍스트 설정
        for i in range(1, 21):  # 20개의 게시글을 생성합니다.
            post = Post(
                title=f"테스트 게시글 {i}",
                content=f"이것은 테스트용 게시글 {i}의 내용입니다.",
                ip="00000000"  # 예시로 IP를 "00000000"으로 설정했습니다.
            )
            db.session.add(post)
        
        db.session.commit()  # 데이터베이스에 저장

if __name__ == "__main__":
    create_test_posts()
    print("20개의 게시글이 생성되었습니다.")
