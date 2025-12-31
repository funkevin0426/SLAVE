from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask import render_template
import hashlib
import math
import dotenv
import os
import google.generativeai as genai
import threading
import requests
from sqlalchemy import or_ , func, desc, and_

# 환경 변수 로드
dotenv.load_dotenv()
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

if not OPENROUTER_API_KEY:
    raise RuntimeError("OPENROUTER_API_KEY 환경변수가 설정되지 않았습니다")

# Gemini AI 설정
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-2.5-flash')

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.environ.get('SECRET_KEY', 'my-very-secret-key-123')

# SQLite DB 경로 설정
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/write")
def write_page():
    return render_template("write.html")

@app.route("/view")
def view_page():
    return render_template("view.html")

@app.route("/admin/login")
def admin_login_page():
    return render_template("admin_login.html")

@app.route("/health")
def health():
    return "Server is running"


def get_client_ip():
    """클라이언트 IP 주소 가져오기 (프록시 X-Forwarded-For 처리 포함)"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr or '0.0.0.0'
    return ip

def mask_ip(ip):
    """IP 주소를 SHA256 해시 후 앞 8자리만 반환 (마스킹 처리)"""
    return hashlib.sha256(ip.encode()).hexdigest()[:8]

# DB 모델 정의
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    ip = db.Column(db.String(50))  # 마스킹된 IP 저장
    edited = db.Column(db.Boolean, default=False)
    grade = db.Column(db.String(20), default='정보 받지 못함')
    tag = db.Column(db.String(20), default='잡글')  # ← 여기에 추가


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    content = db.Column(db.Text)
    ip = db.Column(db.String(50))  # 마스킹된 IP 저장
    edited = db.Column(db.Boolean, default=False)

class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    role = db.Column(db.String(20))
    content = db.Column(db.Text)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(20))  # 'post' or 'comment'
    target_id = db.Column(db.Integer)       # 신고 대상 게시글 또는 댓글 ID
    reason = db.Column(db.String(500))      # 신고 사유
    reporter_ip = db.Column(db.String(50))  # 신고자 IP (마스킹된 상태)

# --- API 엔드포인트 ---

@app.route('/my-ip', methods=['GET'])
def get_my_ip():
    """클라이언트 IP 마스킹된 값 반환"""
    client_ip = get_client_ip()
    masked_ip = mask_ip(client_ip)
    is_admin = session.get('admin', False)
    return jsonify({'ip': masked_ip})

@app.route('/posts', methods=['GET'])
def get_posts():
    is_admin = session.get('admin', False)
    page = int(request.args.get('page', 1))
    query = request.args.get('query', '').strip()
    order = request.args.get('order', 'latest')  # latest, oldest, popular
    tag = request.args.get('tag', '').strip()
    per_page = 20

    base_query = db.session.query(Post, func.count(Comment.id).label('comment_count')) \
        .outerjoin(Comment, Post.id == Comment.post_id) \
        .group_by(Post.id)

    if query:
        base_query = base_query.filter(
            or_(
                Post.title.contains(query),
                Post.content.contains(query),
                Comment.content.contains(query)
            )
        )

    if tag:
        base_query = base_query.filter(Post.tag == tag)

    if order == 'oldest':
        base_query = base_query.order_by(Post.id.asc())
    elif order == 'popular':
        base_query = base_query.order_by(desc('comment_count'))
    else:  # default 최신순
        base_query = base_query.order_by(Post.id.desc())

    total_posts = base_query.count()
    posts = base_query.offset((page - 1) * per_page).limit(per_page).all()
    total_pages = math.ceil(total_posts / per_page)

    return jsonify({
        'posts': [
            {
                'id': p.id,
                'title': p.title,
                'content': p.content,
                'ip': p.ip,
                'grade': p.grade or '정보 받지 못함',
                'tag': p.tag,
                'comment_count': c
            }
            for p, c in posts
        ],
        'total_pages': total_pages
    })


@app.route('/posts', methods=['POST'])
def create_post():
    """새 게시글 생성 후 AI 댓글 자동 생성 (비동기 처리)"""
    data = request.json
    client_ip = get_client_ip()
    masked_ip = mask_ip(client_ip)
    is_admin = session.get('admin', False)
    grade = data.get('grade', '정보 받지 못함')
    tag = data.get('tag', '정보 받지 못함')

    post = Post(title=data['title'], content=data['content'], ip=masked_ip, grade=grade, tag = tag)
    db.session.add(post)
    db.session.commit()

    ai_choices = data.get('ai_choices', [])

    def generate_ai_comment(post_id, title, content, ai_choices, grade):
        with app.app_context():
            prompt = f"""이 글이 한 질문에 대해 {grade} 수준에서 자세하게 해설해줘. 형식은 
안녕하세요! 아무튼 쩌는 AI, SLAVE입니다! 질문하신 내용에 대해 답변드리겠습니다!
(여기에 내용을 넣어줘)
도움이 되셨나요? 저는 개발자가 현타와서 서비스를 종료하거나 님들이 개 태러짓 해서 api를 다 써버리지 않는 한 여러분들을 계속 도와줄 것입니다! 감사합니다!
이런 식으로 해줘. 아래는 그 글이야

제목: {title}
내용: {content}
"""

            ai_comments = []

            # Gemini AI 호출
            if 'gemini' in ai_choices:
                try:
                    history_records = ChatHistory.query.filter_by(post_id=post_id).all()
                    history = [{"role": h.role, "parts": [h.content]} for h in history_records]
                    chat = model.start_chat(history=history)
                    response = chat.send_message(prompt)
                    ai_comment = response.text.strip()

                    db.session.add(ChatHistory(post_id=post_id, role="user", content=prompt))
                    db.session.add(ChatHistory(post_id=post_id, role="model", content=ai_comment))

                    if ai_comment:
                        ai_comments.append(("Gemini", ai_comment))
                except Exception as e:
                    print("Gemini 응답 오류:", e)
                    comment = Comment(post_id=post_id, content=f"[오류로그(Gemini))]\n오류가 발생하였습니다.\n오류코드: {e}\n개발자의 개같은 로동이 확정되었으니 개발자에게 연락주세요.\n아이런개같은거 - 박지후", ip="SLAVE")
                    db.session.add(comment)

            # Deepseek API 호출
            if 'deepseek' in ai_choices:
                try:
                    headers = {
                        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                        "Content-Type": "application/json",
                        "X-Title": "Flask Forum App"
                    }

                    data_deepseek = {
                        "model": "deepseek/deepseek-chat",
                        "messages": [{"role": "user", "content": prompt}]
                    }
                    resp = requests.post("https://openrouter.ai/api/v1/chat/completions", json=data_deepseek, headers=headers)
                    if resp.status_code == 200:
                        deepseek_comment = resp.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                        if deepseek_comment:
                            ai_comments.append(("Deepseek", deepseek_comment))
                    else:
                        print("Deepseek 오류 코드:", resp.status_code)
                        comment = Comment(post_id=post_id, content=f"[오류로그(Deepseek)]\n오류가 발생하였습니다.\n오류코드: {resp.status_code}\n개발자의 개같은 로동이 확정되었으니 개발자에게 연락주세요.\n아이런개같은거 - 박지후", ip="SLAVE")
                        db.session.add(comment)
                except Exception as e:
                    print("Deepseek API 호출 오류:", e)
                    comment = Comment(post_id=post_id, content=f"[오류로그(Deepseek)]\napi 호출 오류가 발생하였습니다.\n오류코드: {e}\n개발자의 개같은 로동이 확정되었으니 개발자에게 연락주세요.\n아이런개같은거 - 박지후", ip="SLAVE")
                    db.session.add(comment)

            # AI 댓글 DB 저장 (작성자는 'SLAVE' 고정)
            for source, comment_text in ai_comments:
                comment = Comment(post_id=post_id, content=f"[{source} AI]\n{comment_text}", ip="SLAVE")
                db.session.add(comment)

            db.session.commit()

    # AI 댓글 생성 비동기 처리
    threading.Thread(target=generate_ai_comment, args=(post.id, data['title'], data['content'], ai_choices, grade)).start()

    return jsonify({'message': 'Post created'}), 201

@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    """게시글 상세 정보 및 댓글 조회"""
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.id).all()
    client_ip = get_client_ip()
    masked_ip = mask_ip(client_ip)
    is_admin = session.get('admin', False)
    
    return jsonify({
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'tag': post.tag,
        'ip': post.ip,
        'my_ip': masked_ip,
        'edited': post.edited,
        'grade': post.grade or '정보 받지 못함',
        'comments': [{'id': c.id, 'content': c.content, 'ip': c.ip, 'edited': c.edited} for c in comments]
    })

@app.route('/posts/<int:post_id>', methods=['PUT'])
def update_post(post_id):
    """게시글 수정 (작성자 IP와 비교 후 권한 체크)"""
    post = Post.query.get_or_404(post_id)
    client_ip = get_client_ip()
    masked_ip = mask_ip(client_ip)
    is_admin = session.get('admin', False)
    if not session.get('admin') and post.ip != masked_ip:
        return jsonify({'error': '권한이 없습니다.'}), 403
    data = request.json
    post.title = data['title']
    post.content = data['content']
    post.edited = True
    db.session.commit()
    return jsonify({'message': '게시글이 수정되었습니다.'})

@app.route('/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    """게시글 삭제 및 관련 댓글, 채팅 기록 삭제 (권한 체크 포함)"""
    post = Post.query.get_or_404(post_id)
    client_ip = get_client_ip()
    masked_ip = mask_ip(client_ip)
    is_admin = session.get('admin', False)
    if not session.get('admin') and post.ip != masked_ip:
        return jsonify({'error': '권한이 없습니다.'}), 403
    Comment.query.filter_by(post_id=post_id).delete()
    ChatHistory.query.filter_by(post_id=post_id).delete()
    db.session.delete(post)
    db.session.commit()
    return jsonify({'message': '게시글이 삭제되었습니다.'})

@app.route('/posts/<int:post_id>/comments', methods=['POST'])
def add_comment(post_id):
    """댓글 추가"""
    data = request.json
    client_ip = get_client_ip()
    masked_ip = mask_ip(client_ip)
    is_admin = session.get('admin', False)
    
    comment = Comment(post_id=post_id, content=data['content'], ip=masked_ip)
    db.session.add(comment)
    db.session.commit()
    return jsonify({'id': comment.id, 'content': comment.content, 'ip': comment.ip}), 201

@app.route('/comments/<int:comment_id>', methods=['PUT'])
def update_comment(comment_id):
    """댓글 수정 (작성자 IP와 비교 후 권한 체크)"""
    comment = Comment.query.get_or_404(comment_id)
    client_ip = get_client_ip()
    masked_ip = mask_ip(client_ip)
    is_admin = session.get('admin', False)
    if comment.ip != masked_ip:
        return jsonify({'error': '권한이 없습니다.'}), 403
    data = request.json
    comment.content = data['content']
    comment.edited = True
    db.session.commit()
    return jsonify({'message': '댓글이 수정되었습니다.'})

@app.route('/comments/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    """댓글 삭제 (작성자 IP와 비교 후 권한 체크)"""
    comment = Comment.query.get_or_404(comment_id)
    client_ip = get_client_ip()
    masked_ip = mask_ip(client_ip)
    is_admin = session.get('admin', False)
    if comment.ip != masked_ip:
        return jsonify({'error': '권한이 없습니다.'}), 403
    db.session.delete(comment)
    db.session.commit()
    return jsonify({'message': '댓글이 삭제되었습니다.'})

@app.route('/report', methods=['POST'])
def report():
    """게시글 또는 댓글 신고 접수"""
    data = request.json
    report_type = data.get('report_type')
    target_id = data.get('target_id')
    reason = data.get('reason', '').strip()

    if not report_type or not target_id or not reason:
        return jsonify({'error': '필수 데이터가 없습니다.'}), 400

    reporter_ip = mask_ip(get_client_ip())

    # 신고 저장
    report = Report(report_type=report_type, target_id=target_id, reason=reason, reporter_ip=reporter_ip)
    db.session.add(report)
    db.session.commit()

    # 임시 출력 (백엔드 로그용)
    if report_type == 'post':
        post = Post.query.get(target_id)
        if post:
            print(f"게시글 신고 - 작성자: {post.ip}, 제목: {post.title}, 내용: {post.content}, 사유: {reason}")
    elif report_type == 'comment':
        comment = Comment.query.get(target_id)
        if comment:
            print(f"댓글 신고 - 작성자: {comment.ip}, 내용: {comment.content}, 사유: {reason}")

    return jsonify({'message': '신고가 접수되었습니다.'})

# 👇 여기에 이어서 기능 확장: 정렬, 태그, 댓글 검색, 관리자 권한 구현


# Post 모델에 태그 필드 추가 (기존 코드 수정 필요)
if not hasattr(Post, 'tag'):
    Post.tag = db.Column(db.String(20), default='잡글')

# 관리자 인증용 계정 (간단 구현)
ADMIN_USERNAME = '신이난케빈이'
ADMIN_PASSWORD = '!qkrwlgn0'  # 실제 서비스에서는 암호화 필요
app.secret_key = 'your_secret_key_here'

@app.route('/check-admin')
def check_admin():
    return jsonify({'is_admin': session.get('admin', False)})

@app.route('/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('id')  # 클라이언트에서 'id'로 보냄
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': '입력 누락'}), 400

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin'] = True
        return jsonify({'message': '로그인 성공'})
    else:
        return jsonify({'error': '아이디 또는 비밀번호가 틀렸습니다.'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return jsonify({'message': '로그아웃 완료'})

@app.route('/admin/status', methods=['GET'])
def admin_status():
    return jsonify({'is_admin': session.get('admin', False)})

@app.route('/admin/reports', methods=['GET'])
def get_reports():
    if not session.get('admin'):
        return jsonify({'error': '관리자 권한이 필요합니다.'}), 403

    reports = Report.query.order_by(Report.id.desc()).all()
    result = []
    for r in reports:
        item = {
            'id': r.id,
            'type': r.report_type,
            'target_id': r.target_id,
            'reason': r.reason,
            'reporter_ip': r.reporter_ip
        }
        if r.report_type == 'post':
            post = Post.query.get(r.target_id)
            if post:
                item['target_title'] = post.title
        elif r.report_type == 'comment':
            comment = Comment.query.get(r.target_id)
            if comment:
                item['target_content'] = comment.content
        result.append(item)
    return jsonify({'reports': result})

with app.app_context():
    db.create_all()
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
