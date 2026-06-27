import json
import sqlite3
import hashlib
import os
import time
import secrets
from flask import Flask, request, Response, jsonify, stream_with_context, session, render_template_string
from flask_cors import CORS
from threading import Thread
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # 用于 session 加密
CORS(app)

# ===== 管理员配置 =====
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'  # 请修改为强密码

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

def hash_password(password):
    salt = secrets.token_hex(8)
    hash_obj = hashlib.sha256((salt + password).encode())
    return salt, hash_obj.hexdigest()

def verify_password(password, salt, stored_hash):
    return hashlib.sha256((salt + password).encode()).hexdigest() == stored_hash

# ===== 在线用户管理 =====
online_users = {}  # username -> {'ip': ip, 'last_active': timestamp}

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

# ===== 消息队列 =====
pending_messages = []

def broadcast_message(msg):
    pending_messages.append(msg)

# ===== 心跳清理线程 =====
def clean_inactive_users():
    while True:
        time.sleep(60)
        now = time.time()
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

# ===== 管理员认证装饰器 =====
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            return jsonify({'error': '请先登录管理员账号'}), 401
        return f(*args, **kwargs)
    return decorated_function

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
    now = time.time()

    # 判断是否首次登录（当前不在线）
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
    # 只返回消息内容（不含id）
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
    # 公开接口只返回内容，不返回id
    return jsonify([{'type': m['type'], 'nickname': m['nickname'], 'content': m['content'], 'timestamp': m['timestamp']} for m in msgs]), 200

# ===== 管理员路由 =====

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
    """管理页面 HTML"""
    if not session.get('admin'):
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>管理员登录</title></head>
        <body>
            <h2>管理员登录</h2>
            <input id="user" placeholder="用户名" value="admin"><br>
            <input id="pass" type="password" placeholder="密码" value="admin123"><br>
            <button onclick="login()">登录</button>
            <div id="msg"></div>
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
                        document.getElementById('msg').innerText = '登录失败: ' + data.error;
                    }
                }
            </script>
        </body>
        </html>
        '''
    # 管理员已登录，显示管理界面
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>后台管理</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            h1 { color: #333; }
            .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background: #f2f2f2; }
            .btn { background: #e74c3c; color: white; border: none; padding: 4px 10px; border-radius: 4px; cursor: pointer; }
            .btn:hover { background: #c0392b; }
            .logout { float: right; background: #3498db; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }
            .logout:hover { background: #2980b9; }
        </style>
    </head>
    <body>
        <h1>后台管理 <button class="logout" onclick="logout()">退出管理</button></h1>
        <div class="section">
            <h2>注册用户</h2>
            <table id="usersTable">
                <tr><th>ID</th><th>用户名</th><th>密码哈希</th><th>盐</th><th>操作</th></tr>
            </table>
        </div>
        <div class="section">
            <h2>聊天记录</h2>
            <table id="messagesTable">
                <tr><th>ID</th><th>类型</th><th>昵称</th><th>内容</th><th>时间戳</th><th>操作</th></tr>
            </table>
        </div>
        <div class="section">
            <h2>在线用户</h2>
            <div id="onlineUsers"></div>
        </div>
        <script>
            async function fetchData() {
                // 获取用户列表
                const usersResp = await fetch('/admin/api/users');
                const users = await usersResp.json();
                let usersHtml = '<tr><th>ID</th><th>用户名</th><th>密码哈希</th><th>盐</th><th>操作</th></tr>';
                users.forEach(u => {
                    usersHtml += `<tr>
                        <td>${u.id}</td>
                        <td>${u.username}</td>
                        <td>${u.password_hash}</td>
                        <td>${u.salt}</td>
                        <td><button class="btn" onclick="deleteUser(${u.id})">删除</button></td>
                    </tr>`;
                });
                document.getElementById('usersTable').innerHTML = usersHtml;

                // 获取消息列表
                const msgsResp = await fetch('/admin/api/messages');
                const msgs = await msgsResp.json();
                let msgsHtml = '<tr><th>ID</th><th>类型</th><th>昵称</th><th>内容</th><th>时间戳</th><th>操作</th></tr>';
                msgs.forEach(m => {
                    const time = new Date(m.timestamp).toLocaleString();
                    msgsHtml += `<tr>
                        <td>${m.id}</td>
                        <td>${m.type}</td>
                        <td>${m.nickname}</td>
                        <td>${m.content}</td>
                        <td>${time}</td>
                        <td><button class="btn" onclick="deleteMessage(${m.id})">删除</button></td>
                    </tr>`;
                });
                document.getElementById('messagesTable').innerHTML = msgsHtml;

                // 获取在线用户
                const onlineResp = await fetch('/admin/api/online');
                const online = await onlineResp.json();
                document.getElementById('onlineUsers').innerHTML = online.length ? online.join(', ') : '无';
            }

            async function deleteUser(id) {
                if (!confirm('确认删除该用户？')) return;
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

            async function logout() {
                await fetch('/admin/logout', {method: 'POST'});
                window.location.href = '/admin';
            }

            fetchData();
            setInterval(fetchData, 5000); // 每5秒刷新
        </script>
    </body>
    </html>
    '''

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

@app.route('/admin/api/delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': '缺少用户ID'}), 400
    # 禁止删除管理员自身（假设管理员id为1）
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