import json
import sqlite3
import hashlib
import os
import time
import secrets
from flask import Flask, request, Response, jsonify, stream_with_context
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # 允许跨域

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

# ===== 在线用户管理（基于IP限制，每个IP只能一个账号） =====
online_users = {}  # ip -> username

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

# ===== SSE 推送 =====
# 存储每个客户端的响应流（用于推送）
clients = []  # 存储 (ip, response) 但实际使用 Flask 的 stream_with_context

# 使用全局消息队列（简单列表，实际生产可用 Redis）
pending_messages = []

def broadcast_message(msg):
    """将消息加入待推送队列，并通知所有客户端"""
    pending_messages.append(msg)
    # 由于 SSE 是长连接，我们通过生成器持续检查 pending_messages
    # 但无法主动通知，所以只能依靠客户端每帧的等待循环。

# ===== 路由 =====

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': '用户名和密码必填'}), 400
    # 检查是否已存在
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

    # 检查IP是否已被占用（每个设备只能一个账号）
    client_ip = request.remote_addr
    if client_ip in online_users and online_users[client_ip] != username:
        return jsonify({'error': f'该设备已登录账号 "{online_users[client_ip]}"，请先退出'}), 403

    # 登录成功
    # 如果该IP已有账号且是自己，则更新（避免重复）
    online_users[client_ip] = username

    # 系统消息：用户加入
    save_message('system', username, f'👋 {username} 加入了聊天室')
    broadcast_message({'type': 'system', 'content': f'👋 {username} 加入了聊天室', 'timestamp': int(time.time()*1000)})

    # 返回成功，并告知当前所有在线用户列表
    return jsonify({
        'message': '登录成功',
        'username': username,
        'users': list(online_users.values())
    }), 200

@app.route('/logout', methods=['POST'])
def logout():
    data = request.get_json()
    username = data.get('username')
    client_ip = request.remote_addr
    if client_ip in online_users and online_users[client_ip] == username:
        del online_users[client_ip]
        save_message('system', username, f'🚶 {username} 离开了聊天室')
        broadcast_message({'type': 'system', 'content': f'🚶 {username} 离开了聊天室', 'timestamp': int(time.time()*1000)})
        return jsonify({'message': '已退出'}), 200
    return jsonify({'error': '未登录'}), 401

@app.route('/message', methods=['POST'])
def send_message():
    data = request.get_json()
    username = data.get('nickname')
    content = data.get('content')
    if not username or not content:
        return jsonify({'error': '缺少参数'}), 400
    # 验证该用户是否在线（可选）
    client_ip = request.remote_addr
    if client_ip not in online_users or online_users[client_ip] != username:
        return jsonify({'error': '未登录或账号不一致'}), 401

    # 保存消息
    ts = save_message('message', username, content)
    broadcast_message({'type': 'message', 'nickname': username, 'content': content, 'timestamp': ts})
    return jsonify({'message': '发送成功'}), 200

@app.route('/stream')
def stream():
    """SSE 事件流"""
    client_ip = request.remote_addr
    # 获取历史消息（最多50条）
    all_msgs = get_all_messages()
    # 只保留最近50条，避免一次性发送太多
    if len(all_msgs) > 50:
        all_msgs = all_msgs[-50:]

    def event_stream():
        # 先发送历史消息
        for msg in all_msgs:
            yield f"data: {json.dumps(msg)}\n\n"
        # 然后持续监听新消息
        last_id = len(all_msgs)  # 简单计数，用于标记已发送
        while True:
            # 检查全局 pending_messages 是否有新消息
            # 为了避免频繁循环，使用 time.sleep
            time.sleep(0.5)
            # 检查是否有新消息（从数据库获取最新）
            # 更高效：使用队列，但为了简化，我们从数据库读取最新ID
            conn = sqlite3.connect(CHAT_DB)
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM messages')
            count = c.fetchone()[0]
            conn.close()
            if count > last_id:
                # 有新消息，获取新消息
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
    return jsonify(list(online_users.values())), 200

@app.route('/messages', methods=['GET'])
def get_messages():
    # 用于初始加载
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
    print(f"✅ 服务器启动，监听 0.0.0.0:8080")
    print(f"📡 本机IP: {ip}")
    print("📌 前端用这个IP连接即可")
    app.run(host='0.0.0.0', port=8080, threaded=True)