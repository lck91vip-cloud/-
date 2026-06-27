import json
import sqlite3
import hashlib
import os
import time
import secrets
from flask import Flask, request, Response, jsonify, stream_with_context, session
from flask_cors import CORS
from threading import Thread
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app)

# ===== 管理员配置 =====
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'  # 请立即修改为强密码！

BASE_DIR = './liaotian'
KEY_DIR = os.path.join(BASE_DIR, 'key')
RECORD_DIR = os.path.join(BASE_DIR, 'record')
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(RECORD_DIR, exist_ok=True)

USER_DB = os.path.join(KEY_DIR, 'users.db')
CHAT_DB = os.path.join(RECORD_DIR, 'chat.db')

# ----- 数据库初始化 -----
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

def init_ban_db():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS bans (
            username TEXT PRIMARY KEY,
            ban_until INTEGER  -- -1 表示永久
        )
    ''')
    conn.commit()
    conn.close()

init_user_db()
init_chat_db()
init_ban_db()

# ----- 密码工具 -----
def hash_password(password):
    salt = secrets.token_hex(8)
    hash_obj = hashlib.sha256((salt + password).encode())
    return salt, hash_obj.hexdigest()

def verify_password(password, salt, stored_hash):
    return hashlib.sha256((salt + password).encode()).hexdigest() == stored_hash

# ----- 在线用户管理 -----
online_users = {}  # username -> {'ip': ip, 'last_active': timestamp}

# ----- 消息存储 -----
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
    c.execute('SELECT id, type, nickname, content, timestamp FROM messages ORDER BY id')
    rows = c.fetchall()
    conn.close()
    return [{'id': r[0], 'type': r[1], 'nickname': r[2], 'content': r[3], 'timestamp': r[4]} for r in rows]

def get_all_users():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('SELECT id, username, password_hash, salt FROM users ORDER BY id')
    rows = c.fetchall()
    conn.close()
    return [{'id': r[0], 'username': r[1], 'password_hash': r[2], 'salt': r[3]} for r in rows]

def delete_user(user_id):
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()

def delete_message(msg_id):
    conn = sqlite3.connect(CHAT_DB)
    c = conn.cursor()
    c.execute('DELETE FROM messages WHERE id=?', (msg_id,))
    conn.commit()
    conn.close()

# ----- 封禁管理 -----
def get_ban(username):
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('SELECT ban_until FROM bans WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def set_ban(username, ban_until):
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('REPLACE INTO bans (username, ban_until) VALUES (?, ?)', (username, ban_until))
    conn.commit()
    conn.close()

def remove_ban(username):
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('DELETE FROM bans WHERE username=?', (username,))
    conn.commit()
    conn.close()

def get_all_bans():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('SELECT username, ban_until FROM bans')
    rows = c.fetchall()
    conn.close()
    return [{'username': r[0], 'ban_until': r[1]} for r in rows]

def clean_expired_bans():
    """清理已过期的封禁记录（临时封禁到期）"""
    now = int(time.time())
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute('DELETE FROM bans WHERE ban_until != -1 AND ban_until <= ?', (now,))
    conn.commit()
    conn.close()

# ----- 消息队列 & 广播 -----
pending_messages = []

def broadcast_message(msg):
    pending_messages.append(msg)

# ----- 后台清理线程 -----
def clean_inactive_users():
    while True:
        time.sleep(60)
        now = time.time()
        # 清理过期封禁
        clean_expired_bans()
        # 清理超时在线用户
        to_remove = []
        for username, info in online_users.items():
            if now - info['last_active'] > 300:  # 5 分钟
                to_remove.append(username)
        for username in to_remove:
            del online_users[username]
            save_message('system', username, f'🚶 {username} 超时离开聊天室')
            broadcast_message({
                'type': 'system',
                'content': f'🚶 {username} 超时离开聊天室',
                'timestamp': int(time.time() * 1000)
            })

Thread(target=clean_inactive_users, daemon=True).start()

# ----- 管理员认证装饰器 -----
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            return jsonify({'error': '请先登录管理员账号'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
#  路由
# ============================================================

@app.route('/')
def index():
    """返回聊天页面"""
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            html = f.read()
        return html, 200, {'Content-Type': 'text/html; charset=utf-8'}
    except FileNotFoundError:
        return jsonify({'error': 'index.html not found'}), 404

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

    # 检查封禁
    ban_until = get_ban(username)
    if ban_until is not None:
        if ban_until == -1:
            return jsonify({'error': '该账号已被永久封禁'}), 403
        elif ban_until > int(time.time()):
            remaining = (ban_until - int(time.time())) // 3600
            return jsonify({'error': f'该账号已被封禁，剩余 {remaining} 小时'}), 403
        else:
            remove_ban(username)  # 自动解封

    client_ip = request.remote_addr
    now = time.time()

    is_new = username not in online_users
    online_users[username] = {'ip': client_ip, 'last_active': now}

    if is_new:
        save_message('system', username, f'👋 {username} 加入了聊天室')
        broadcast_message({
            'type': 'system',
            'content': f'👋 {username} 加入了聊天室',
            'timestamp': int(now * 1000)
        })

    return jsonify({
        'message': '登录成功',
        'username': username,
        'users': list(online_users.keys())
    }), 200

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    data = request.get_json()
    username = data.get('username')
    if username and username in online_users:
        online_users[username]['last_active'] = time.time()
        return jsonify({'status': 'ok'}), 200
    return jsonify({'error': '未登录'}), 401

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
    if username not in online_users:
        return jsonify({'error': '未登录或账号不一致'}), 401

    ts = save_message('message', username, content)
    broadcast_message({
        'type': 'message',
        'nickname': username,
        'content': content,
        'timestamp': ts
    })
    online_users[username]['last_active'] = time.time()
    return jsonify({'message': '发送成功'}), 200

@app.route('/stream')
def stream():
    all_msgs = get_all_messages()
    msgs_for_stream = [{'type': m['type'], 'nickname': m['nickname'], 'content': m['content'], 'timestamp': m['timestamp']} for m in all_msgs[-50:]]
    def event_stream():
        for msg in msgs_for_stream:
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
                c.execute('SELECT id, type, nickname, content, timestamp FROM messages WHERE id > ?', (last_id,))
                new_rows = c.fetchall()
                conn.close()
                for r in new_rows:
                    msg = {'type': r[1], 'nickname': r[2], 'content': r[3], 'timestamp': r[4]}
                    yield f"data: {json.dumps(msg)}\n\n"
                last_id = count
    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

@app.route('/users', methods=['GET'])
def get_users():
    return jsonify(list(online_users.keys())), 200

@app.route('/messages', methods=['GET'])
def get_messages_public():
    msgs = get_all_messages()
    return jsonify([{'type': m['type'], 'nickname': m['nickname'], 'content': m['content'], 'timestamp': m['timestamp']} for m in msgs]), 200

# ============================================================
#  管理员后台（包含踢出、封禁、解封、IP显示等完整功能）
# ============================================================

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin'] = True
        return jsonify({'message': '登录成功'}), 200
    else:
        return jsonify({'error': '用户名或密码错误'}), 401

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin', None)
    return jsonify({'message': '已退出'}), 200

@app.route('/admin')
def admin_panel():
    if not session.get('admin'):
        # 登录页面
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>管理员登录</title>
            <style>
                * { margin:0; padding:0; box-sizing:border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    background: linear-gradient(135deg, #e8f0fe 0%, #d4e4f7 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .login-card {
                    background: white;
                    border-radius: 24px;
                    box-shadow: 0 20px 60px rgba(0,20,50,0.15);
                    padding: 40px 32px;
                    max-width: 400px;
                    width: 100%;
                }
                .login-card h2 { font-size:24px; font-weight:600; color:#1a2634; text-align:center; margin-bottom:8px; }
                .login-card .sub { text-align:center; color:#7a8a9e; font-size:14px; margin-bottom:28px; }
                .login-card input {
                    width:100%; padding:12px 16px; border:2px solid #e6ecf3; border-radius:12px;
                    font-size:15px; outline:none; transition:border 0.2s; background:#f7f9fc; margin-bottom:16px;
                }
                .login-card input:focus { border-color:#2d7aff; background:white; box-shadow:0 0 0 4px rgba(45,122,255,0.1); }
                .login-card button {
                    width:100%; padding:12px; background:#2d7aff; color:white; border:none; border-radius:14px;
                    font-size:16px; font-weight:600; cursor:pointer; transition:background 0.2s;
                }
                .login-card button:hover { background:#1a5fd9; }
                .login-card .msg { margin-top:14px; text-align:center; color:#ef5350; font-size:14px; min-height:20px; }
            </style>
        </head>
        <body>
            <div class="login-card">
                <h2>🔐 管理员登录</h2>
                <div class="sub">请输入管理员凭证</div>
                <input id="user" placeholder="用户名" value="admin">
                <input id="pass" type="password" placeholder="密码" value="admin123">
                <button onclick="login()">登录</button>
                <div class="msg" id="msg"></div>
            </div>
            <script>
                async function login() {
                    const username = document.getElementById('user').value;
                    const password = document.getElementById('pass').value;
                    const resp = await fetch('/admin/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username, password})
                    });
                    const data = await resp.json();
                    if (resp.ok) {
                        window.location.href = '/admin';
                    } else {
                        document.getElementById('msg').innerText = '❌ ' + data.error;
                    }
                }
                document.getElementById('pass').addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
                document.getElementById('user').addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
            </script>
        </body>
        </html>
        '''

    # 管理主界面（含在线用户IP、踢出、封禁、封禁列表等）
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>后台管理</title>
        <style>
            * { margin:0; padding:0; box-sizing:border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f2f6fc; padding: 20px; color: #1a2634; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header {
                display: flex; justify-content: space-between; align-items: center;
                background: white; padding: 16px 28px; border-radius: 16px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.04); margin-bottom: 24px;
            }
            .header h1 { font-size: 22px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
            .logout-btn {
                background: #ef5350; color: white; border: none; padding: 8px 20px;
                border-radius: 10px; font-size: 14px; cursor: pointer; transition: background 0.2s;
                font-weight: 500;
            }
            .logout-btn:hover { background: #c62828; }
            .card {
                background: white; border-radius: 16px; box-shadow: 0 2px 8px rgba(0,0,0,0.04);
                padding: 20px 24px 28px; margin-bottom: 24px; overflow-x: auto;
            }
            .card h2 {
                font-size: 18px; font-weight: 600; color: #2c3e50; margin-bottom: 16px;
                display: flex; align-items: center; gap: 10px;
            }
            .badge {
                background: #e8f0fe; color: #2d7aff; font-size: 13px; font-weight: 500;
                padding: 2px 12px; border-radius: 20px;
            }
            table { width: 100%; border-collapse: collapse; font-size: 14px; }
            th {
                text-align: left; padding: 12px 12px 12px 0;
                border-bottom: 2px solid #e6ecf3; color: #5a6a7e; font-weight: 600;
                background: #fafcfe;
            }
            td { padding: 12px 12px 12px 0; border-bottom: 1px solid #eef2f7; vertical-align: middle; }
            tr:hover td { background: #f8faff; }
            .btn {
                background: #ef5350; color: white; border: none; padding: 4px 14px;
                border-radius: 8px; cursor: pointer; font-size: 13px;
                transition: background 0.2s; font-weight: 500;
            }
            .btn:hover { background: #c62828; }
            .btn-success { background: #2d7aff; }
            .btn-success:hover { background: #1a5fd9; }
            .btn-warning { background: #ffa726; }
            .btn-warning:hover { background: #f57c00; }
            .empty { color: #9aabbf; padding: 16px 0; text-align: center; }
            .timestamp { color: #7a8a9e; font-size: 13px; }
            @media (max-width: 600px) {
                .header { flex-direction: column; align-items: flex-start; gap: 12px; }
                .card { padding: 16px; }
                table { font-size: 13px; }
                th, td { padding: 8px 6px; }
                .btn { padding: 3px 10px; font-size: 12px; }
            }
            .ip-cell { font-family: monospace; color: #555; }
            .action-btns .btn { margin-right: 4px; margin-bottom: 2px; }
        </style>
    </head>
    <body>
    <div class="container">
        <div class="header">
            <h1>🛠️ 管理面板</h1>
            <button class="logout-btn" onclick="logout()">退出管理</button>
        </div>

        <!-- 注册用户 -->
        <div class="card">
            <h2>👥 注册用户 <span class="badge" id="userCount">0</span></h2>
            <div style="overflow-x:auto;">
                <table id="usersTable">
                    <thead><tr><th>ID</th><th>用户名</th><th>密码哈希</th><th>盐</th><th>操作</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <!-- 聊天记录 -->
        <div class="card">
            <h2>💬 聊天记录 <span class="badge" id="msgCount">0</span></h2>
            <div style="overflow-x:auto;">
                <table id="messagesTable">
                    <thead><tr><th>ID</th><th>类型</th><th>昵称</th><th>内容</th><th>时间</th><th>操作</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <!-- 在线用户（含 IP 和踢出/封禁） -->
        <div class="card">
            <h2>🟢 在线用户 <span class="badge" id="onlineCount">0</span></h2>
            <div style="overflow-x:auto;">
                <table id="onlineTable">
                    <thead><tr><th>用户名</th><th>IP 地址</th><th>操作</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <!-- 封禁列表 -->
        <div class="card">
            <h2>⛔ 封禁列表 <span class="badge" id="banCount">0</span></h2>
            <div style="overflow-x:auto;">
                <table id="banTable">
                    <thead><tr><th>用户名</th><th>剩余时间</th><th>操作</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // ---------- 数据获取 ----------
        async function fetchData() {
            // 用户列表
            const usersResp = await fetch('/admin/api/users');
            const users = await usersResp.json();
            let usersBody = '';
            users.forEach(u => {
                usersBody += `<tr>
                    <td>${u.id}</td>
                    <td><strong>${u.username}</strong></td>
                    <td style="font-family:monospace;font-size:13px;color:#555;">${u.password_hash}</td>
                    <td style="font-family:monospace;font-size:13px;color:#555;">${u.salt}</td>
                    <td><button class="btn" onclick="deleteUser(${u.id})">删除</button></td>
                </tr>`;
            });
            document.querySelector('#usersTable tbody').innerHTML = usersBody || `<tr><td colspan="5" class="empty">暂无用户</td></tr>`;
            document.getElementById('userCount').textContent = users.length;

            // 消息列表
            const msgsResp = await fetch('/admin/api/messages');
            const msgs = await msgsResp.json();
            let msgsBody = '';
            msgs.forEach(m => {
                const time = new Date(m.timestamp).toLocaleString();
                msgsBody += `<tr>
                    <td>${m.id}</td>
                    <td>${m.type}</td>
                    <td>${m.nickname}</td>
                    <td>${m.content || ''}</td>
                    <td class="timestamp">${time}</td>
                    <td><button class="btn" onclick="deleteMessage(${m.id})">删除</button></td>
                </tr>`;
            });
            document.querySelector('#messagesTable tbody').innerHTML = msgsBody || `<tr><td colspan="6" class="empty">暂无消息</td></tr>`;
            document.getElementById('msgCount').textContent = msgs.length;

            // 在线用户（含 IP）
            const onlineResp = await fetch('/admin/api/online_detail');
            const online = await onlineResp.json();
            let onlineBody = '';
            online.forEach(u => {
                onlineBody += `<tr>
                    <td><strong>${u.username}</strong></td>
                    <td class="ip-cell">${u.ip}</td>
                    <td class="action-btns">
                        <button class="btn btn-warning" onclick="kickUser('${u.username}')">踢出</button>
                        <button class="btn" onclick="banUser('${u.username}')">封禁</button>
                    </td>
                </tr>`;
            });
            document.querySelector('#onlineTable tbody').innerHTML = onlineBody || `<tr><td colspan="3" class="empty">当前没有用户在线</td></tr>`;
            document.getElementById('onlineCount').textContent = online.length;

            // 封禁列表
            const bansResp = await fetch('/admin/api/bans');
            const bans = await bansResp.json();
            let bansBody = '';
            bans.forEach(b => {
                bansBody += `<tr>
                    <td><strong>${b.username}</strong></td>
                    <td>${b.remaining}</td>
                    <td><button class="btn btn-success" onclick="unbanUser('${b.username}')">解封</button></td>
                </tr>`;
            });
            document.querySelector('#banTable tbody').innerHTML = bansBody || `<tr><td colspan="3" class="empty">暂无封禁记录</td></tr>`;
            document.getElementById('banCount').textContent = bans.length;
        }

        // ---------- 操作函数 ----------
        async function deleteUser(id) {
            if (!confirm('确认删除该用户？此操作不可恢复！')) return;
            const resp = await fetch('/admin/api/delete_user', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({user_id: id})
            });
            const data = await resp.json();
            alert(data.message || data.error);
            fetchData();
        }

        async function deleteMessage(id) {
            if (!confirm('确认删除该消息？')) return;
            const resp = await fetch('/admin/api/delete_message', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({msg_id: id})
            });
            const data = await resp.json();
            alert(data.message || data.error);
            fetchData();
        }

        async function kickUser(username) {
            if (!confirm(`确认踢出用户 "${username}" ？`)) return;
            const resp = await fetch('/admin/api/kick', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username})
            });
            const data = await resp.json();
            alert(data.message || data.error);
            fetchData();
        }

        async function banUser(username) {
            const hours = prompt(`输入封禁时长（小时），输入 0 表示永久封禁：`, '24');
            if (hours === null) return;
            const duration = parseInt(hours);
            if (isNaN(duration) || duration < 0) {
                alert('请输入有效的数字（≥0）');
                return;
            }
            if (!confirm(`确认封禁用户 "${username}" ${duration === 0 ? '永久' : duration + ' 小时'} ？`)) return;
            const resp = await fetch('/admin/api/ban', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, duration})
            });
            const data = await resp.json();
            alert(data.message || data.error);
            fetchData();
        }

        async function unbanUser(username) {
            if (!confirm(`确认解封用户 "${username}" ？`)) return;
            const resp = await fetch('/admin/api/unban', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username})
            });
            const data = await resp.json();
            alert(data.message || data.error);
            fetchData();
        }

        async function logout() {
            await fetch('/admin/logout', {method: 'POST'});
            window.location.href = '/admin';
        }

        // 初次加载 + 定时刷新
        fetchData();
        setInterval(fetchData, 5000);
    </script>
    </body>
    </html>
    '''

# ----- 管理员 API -----
@app.route('/admin/api/users')
@admin_required
def admin_users():
    return jsonify(get_all_users()), 200

@app.route('/admin/api/messages')
@admin_required
def admin_messages():
    msgs = get_all_messages()
    return jsonify(msgs), 200

@app.route('/admin/api/online')
@admin_required
def admin_online():
    return jsonify(list(online_users.keys())), 200

@app.route('/admin/api/online_detail')
@admin_required
def admin_online_detail():
    # 返回用户名和IP的列表
    return jsonify([{'username': u, 'ip': info['ip']} for u, info in online_users.items()]), 200

@app.route('/admin/api/delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': '缺少用户ID'}), 400
    if user_id == 1:
        return jsonify({'error': '不能删除管理员账号'}), 403
    delete_user(user_id)
    return jsonify({'message': '用户已删除'}), 200

@app.route('/admin/api/delete_message', methods=['POST'])
@admin_required
def admin_delete_message():
    data = request.get_json()
    msg_id = data.get('msg_id')
    if not msg_id:
        return jsonify({'error': '缺少消息ID'}), 400
    delete_message(msg_id)
    return jsonify({'message': '消息已删除'}), 200

@app.route('/admin/api/kick', methods=['POST'])
@admin_required
def admin_kick():
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'error': '缺少用户名'}), 400
    if username == ADMIN_USERNAME:
        return jsonify({'error': '不能踢出管理员'}), 403
    if username in online_users:
        del online_users[username]
        save_message('system', '管理员', f'👢 {username} 被管理员踢出')
        broadcast_message({
            'type': 'system',
            'content': f'👢 {username} 被管理员踢出',
            'timestamp': int(time.time() * 1000)
        })
        return jsonify({'message': '用户已踢出'}), 200
    return jsonify({'error': '用户不在线'}), 404

@app.route('/admin/api/ban', methods=['POST'])
@admin_required
def admin_ban():
    data = request.get_json()
    username = data.get('username')
    duration = data.get('duration')  # 小时数，0 表示永久
    if not username:
        return jsonify({'error': '缺少用户名'}), 400
    if username == ADMIN_USERNAME:
        return jsonify({'error': '不能封禁管理员'}), 403
    # 先踢出
    if username in online_users:
        del online_users[username]
        save_message('system', '管理员', f'⛔ {username} 被管理员封禁')
        broadcast_message({
            'type': 'system',
            'content': f'⛔ {username} 被管理员封禁',
            'timestamp': int(time.time() * 1000)
        })
    if duration == 0:
        ban_until = -1
        msg = '永久封禁'
    else:
        ban_until = int(time.time()) + duration * 3600
        msg = f'封禁 {duration} 小时'
    set_ban(username, ban_until)
    return jsonify({'message': f'用户已{msg}'}), 200

@app.route('/admin/api/unban', methods=['POST'])
@admin_required
def admin_unban():
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'error': '缺少用户名'}), 400
    remove_ban(username)
    return jsonify({'message': '用户已解封'}), 200

@app.route('/admin/api/bans', methods=['GET'])
@admin_required
def admin_bans():
    bans = get_all_bans()
    now = int(time.time())
    for b in bans:
        if b['ban_until'] == -1:
            b['remaining'] = '永久'
        else:
            remaining = b['ban_until'] - now
            if remaining > 0:
                hours = remaining // 3600
                b['remaining'] = f'{hours} 小时'
            else:
                b['remaining'] = '已过期（可解封）'
    return jsonify(bans), 200

# ============================================================
#  启动
# ============================================================
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