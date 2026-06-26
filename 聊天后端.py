import json
import sqlite3
import hashlib
import os
import time
import secrets
from flask import Flask, request, Response, jsonify, stream_with_context
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ===== 初始化数据库 =====
BASE_DIR = './liaotian'
KEY_DIR = os.path.join(BASE_DIR, 'key')
RECORD_DIR = os.path.join(BASE_DIR, 'record')
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(RECORD_DIR, exist_ok=True)

USER_DB = os.path.join(KEY_DIR, 'users.db')
CHAT_DB = os.path.join(RECORD_DIR, 'chat.db')

def init_user_db():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def init_chat_db():
    conn = sqlite3.connect(CHAT_DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            nickname TEXT NOT NULL,
            content TEXT,
            timestamp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_user_db()
init_chat_db()

# ===== 密码工具 =====
def hash_password(password):
    salt = secrets.token_hex(8)
    hash_obj = hashlib.sha256((salt + password).encode())
    return salt, hash_obj.hexdigest()

def verify_password(password, salt, stored_hash):
    return hashlib.sha256((salt + password).encode()).hexdigest() == stored_hash

# ===== 在线用户管理（以用户名为键，IP为值） =====
online_users = {}  # username -> ip

# ===== 消息存储 =====
def save_message(msg_type, nickname, content=None):
    conn = sqlite3.connect(CHAT_DB)
    c = conn.cursor()
    ts = int(time.time() * 1000)
    c.execute('INSERT INTO messages (type, nickname, content, timestamp) VALUES (?, ?, ?, ?)',
              (msg_type, nickname, content, ts))
    conn.commit()
    conn.close()
    return ts

def get_all_messages():
    conn = sqlite3.connect(CHAT_DB)
    c = conn.cursor()
    c.execute('SELECT type, nickname, content, timestamp FROM messages ORDER BY id')
    rows = c.fetchall()
    conn.close()
    return [{'type': r[0], 'nickname': r[1], 'content': r[2], 'timestamp': r[3]} for r in rows]

# ===== SSE 消息队列 =====
pending_messages = []

def broadcast_message(msg):
    pending_messages.append(msg)

# ===== 路由 =====

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': '用户名和密码必填'}), 400
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username=?', (username,))
    if c.fetchone():
        conn.close()
        return jsonify({'error': '用户名已存在'}), 409
    salt, pwd_hash = hash_password(password)
    c.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
              (username, pwd_hash, salt))
    conn.commit()
    conn.close()
    return jsonify({'message': '注册成功'}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': '用户名和密码必填'}), 400

    # 验证用户
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('SELECT password_hash, salt FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'error': '用户名或密码错误'}), 401
    stored_hash, salt = row
    if not verify_password(password, salt, stored_hash):
        return jsonify({'error': '用户名或密码错误'}), 401

    client_ip = request.remote_addr

    # 判断是首次登录还是重连
    is_new = username not in online_users
    if is_new:
        # 首次登录：发送系统消息
        save_message('system', username, f'👋 {username} 加入了聊天室')
        broadcast_message({
            'type': 'system',
            'content': f'👋 {username} 加入了聊天室',
            'timestamp': int(time.time() * 1000)
        })
    # 更新在线状态（无论是新登录还是重连）
    online_users[username] = client_ip

    return jsonify({
        'message': '登录成功',
        'username': username,
        'users': list(online_users.keys())
    }), 200

@app.route('/logout', methods=['POST'])
def logout():
    data = request.get_json()
    username = data.get('username')
    if username in online_users:
        del online_users[username]
        save_message('system', username, f'🚶 {username} 离开了聊天室')
        broadcast_message({
            'type': 'system',
            'content': f'🚶 {username} 离开了聊天室',
            'timestamp': int(time.time() * 1000)
        })
        return jsonify({'message': '已退出'}), 200
    return jsonify({'error': '未登录'}), 401

@app.route('/message', methods=['POST'])
def send_message():
    data = request.get_json()
    username = data.get('nickname')
    content = data.get('content')
    if not username or not content:
        return jsonify({'error': '缺少参数'}), 400
    # 检查用户是否在线
    if username not in online_users:
        return jsonify({'error': '未登录或账号不一致'}), 401

    ts = save_message('message', username, content)
    broadcast_message({
        'type': 'message',
        'nickname': username,
        'content': content,
        'timestamp': ts
    })
    return jsonify({'message': '发送成功'}), 200

@app.route('/stream')
def stream():
    """SSE 事件流"""
    all_msgs = get_all_messages()
    if len(all_msgs) > 50:
        all_msgs = all_msgs[-50:]

    def event_stream():
        # 发送历史消息
        for msg in all_msgs:
            yield f"data: {json.dumps(msg)}\n\n"
        last_id = len(all_msgs)
        while True:
            time.sleep(0.5)
            conn = sqlite3.connect(CHAT_DB)
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM messages')
            count = c.fetchone()[0]
            conn.close()
            if count > last_id:
                conn = sqlite3.connect(CHAT_DB)
                c = conn.cursor()
                c.execute('SELECT type, nickname, content, timestamp FROM messages WHERE id > ?', (last_id,))
                new_rows = c.fetchall()
                conn.close()
                for r in new_rows:
                    msg = {'type': r[0], 'nickname': r[1], 'content': r[2], 'timestamp': r[3]}
                    yield f"data: {json.dumps(msg)}\n\n"
                last_id = count

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

@app.route('/users', methods=['GET'])
def get_users():
    return jsonify(list(online_users.keys())), 200

@app.route('/messages', methods=['GET'])
def get_messages():
    msgs = get_all_messages()
    return jsonify(msgs), 200

if __name__ == '__main__':
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    print(f"✅ 服务器启动")
    print(f"📡 本机IP: {ip}")
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, threaded=True)