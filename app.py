"""
校园活动报名系统 - Flask后端应用
高并发Web系统架构设计Demo
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import sqlite3
import hashlib
import time
import random
import string
import threading

app = Flask(__name__)
CORS(app)
app.config['JSON_AS_ASCII'] = False  # 支持中文直接显示
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True  # JSON格式化输出

# ==================== 数据库初始化 ====================
def init_db():
    """初始化SQLite数据库"""
    conn = sqlite3.connect('campus_event.db')
    cursor = conn.cursor()
    
    # 用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            college_id INTEGER NOT NULL,
            email TEXT,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 活动表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            organizer_id INTEGER NOT NULL,
            college_id INTEGER,
            location TEXT,
            start_time DATETIME NOT NULL,
            end_time DATETIME NOT NULL,
            registration_start DATETIME NOT NULL,
            registration_end DATETIME NOT NULL,
            max_participants INTEGER NOT NULL,
            current_participants INTEGER DEFAULT 0,
            status INTEGER DEFAULT 2,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 报名表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registration (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            status INTEGER DEFAULT 1,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(event_id, user_id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect('campus_event.db')
    conn.row_factory = sqlite3.Row
    return conn

# ==================== 内存缓存模拟Redis ====================
class MemoryCache:
    """内存缓存，模拟Redis功能"""
    def __init__(self):
        self._cache = {}
        self._expiry = {}
        self._lock = threading.Lock()
    
    def get(self, key):
        with self._lock:
            if key in self._expiry and time.time() > self._expiry[key]:
                del self._cache[key]
                del self._expiry[key]
                return None
            return self._cache.get(key)
    
    def set(self, key, value, ttl=300):
        with self._lock:
            self._cache[key] = value
            self._expiry[key] = time.time() + ttl
    
    def delete(self, key):
        with self._lock:
            self._cache.pop(key, None)
            self._expiry.pop(key, None)
    
    def incr(self, key):
        with self._lock:
            val = self._cache.get(key, 0)
            self._cache[key] = val + 1
            return self._cache[key]
    
    def decr(self, key):
        with self._lock:
            val = self._cache.get(key, 0)
            self._cache[key] = val - 1
            return self._cache[key]

cache = MemoryCache()

# ==================== 令牌桶限流器 ====================
class TokenBucketRateLimiter:
    """令牌桶算法限流器"""
    def __init__(self, capacity=10, refill_rate=1):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._buckets = {}
        self._lock = threading.Lock()
    
    def allow(self, key):
        """检查是否允许请求"""
        with self._lock:
            now = time.time()
            if key not in self._buckets:
                self._buckets[key] = {'tokens': self.capacity, 'last_refill': now}
            
            bucket = self._buckets[key]
            elapsed = now - bucket['last_refill']
            refill = elapsed * self.refill_rate
            bucket['tokens'] = min(self.capacity, bucket['tokens'] + refill)
            bucket['last_refill'] = now
            
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                return True
            return False

rate_limiter = TokenBucketRateLimiter(capacity=10, refill_rate=2)

# ==================== 验证码服务 ====================
class CaptchaService:
    """验证码服务"""
    def __init__(self):
        self._codes = {}
    
    def generate(self, session_id):
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        self._codes[session_id] = {'code': code, 'time': time.time()}
        return code
    
    def verify(self, session_id, user_input):
        if session_id not in self._codes:
            return False
        stored = self._codes[session_id]
        if time.time() - stored['time'] > 300:  # 5分钟过期
            del self._codes[session_id]
            return False
        result = stored['code'].lower() == user_input.lower()
        if result:
            del self._codes[session_id]
        return result

captcha_service = CaptchaService()

# ==================== 用户服务API ====================
@app.route('/api/user/register', methods=['POST'])
def register():
    """用户注册 - 使用参数化查询防止SQL注入"""
    data = request.json
    password_hash = hashlib.sha256(data['password'].encode()).hexdigest()
    
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO user (student_id, username, password_hash, college_id, email, phone) VALUES (?, ?, ?, ?, ?, ?)',
            (data['student_id'], data['username'], password_hash, data['college_id'], data.get('email'), data.get('phone'))
        )
        conn.commit()
        return jsonify({'success': True, 'message': '注册成功'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': '学号已存在'}), 400
    finally:
        conn.close()

@app.route('/api/user/login', methods=['POST'])
def login():
    """用户登录"""
    data = request.json
    password_hash = hashlib.sha256(data['password'].encode()).hexdigest()
    
    conn = get_db()
    user = conn.execute(
        'SELECT id, username, college_id FROM user WHERE student_id = ? AND password_hash = ?',
        (data['student_id'], password_hash)
    ).fetchone()
    conn.close()
    
    if user:
        session_id = hashlib.md5(f"{user['id']}{time.time()}".encode()).hexdigest()
        cache.set(f"session:{session_id}", dict(user), ttl=1800)
        return jsonify({'success': True, 'session_id': session_id, 'user': dict(user)})
    return jsonify({'success': False, 'message': '学号或密码错误'}), 401

@app.route('/api/user/info', methods=['GET'])
def get_user_info():
    """获取用户信息"""
    session_id = request.headers.get('Authorization')
    user = cache.get(f"session:{session_id}")
    if user:
        return jsonify({'success': True, 'user': user})
    return jsonify({'success': False, 'message': '未登录'}), 401

# ==================== 活动服务API ====================
@app.route('/api/event/list', methods=['GET'])
def list_events():
    """获取活动列表 - 带缓存"""
    cache_key = 'event:list'
    cached = cache.get(cache_key)
    if cached:
        return jsonify({'success': True, 'events': cached, 'from_cache': True})
    
    conn = get_db()
    events = conn.execute('''
        SELECT id, title, description, location, start_time, end_time,
               registration_start, registration_end, max_participants, 
               current_participants, status
        FROM event WHERE status = 2 ORDER BY start_time DESC
    ''').fetchall()
    conn.close()
    
    events_list = [dict(e) for e in events]
    cache.set(cache_key, events_list, ttl=60)
    return jsonify({'success': True, 'events': events_list, 'from_cache': False})

@app.route('/api/event/<int:event_id>', methods=['GET'])
def get_event(event_id):
    """获取活动详情 - 带缓存"""
    cache_key = f'event:{event_id}'
    cached = cache.get(cache_key)
    if cached:
        return jsonify({'success': True, 'event': cached, 'from_cache': True})
    
    conn = get_db()
    event = conn.execute('SELECT * FROM event WHERE id = ?', (event_id,)).fetchone()
    conn.close()
    
    if event:
        event_dict = dict(event)
        cache.set(cache_key, event_dict, ttl=300)
        return jsonify({'success': True, 'event': event_dict, 'from_cache': False})
    return jsonify({'success': False, 'message': '活动不存在'}), 404

@app.route('/api/event/create', methods=['POST'])
def create_event():
    """创建活动"""
    data = request.json
    conn = get_db()
    cursor = conn.execute('''
        INSERT INTO event (title, description, organizer_id, college_id, location,
                          start_time, end_time, registration_start, registration_end, max_participants)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (data['title'], data.get('description'), data['organizer_id'], data.get('college_id'),
          data.get('location'), data['start_time'], data['end_time'],
          data['registration_start'], data['registration_end'], data['max_participants']))
    conn.commit()
    event_id = cursor.lastrowid
    conn.close()
    
    cache.delete('event:list')  # 清除列表缓存
    return jsonify({'success': True, 'event_id': event_id})

# ==================== 报名服务API ====================
@app.route('/api/captcha/generate', methods=['GET'])
def generate_captcha():
    """生成验证码"""
    session_id = request.args.get('session_id', str(time.time()))
    code = captcha_service.generate(session_id)
    return jsonify({'success': True, 'session_id': session_id, 'captcha': code})

@app.route('/api/registration/submit', methods=['POST'])
def submit_registration():
    """提交报名 - 带限流和验证码"""
    data = request.json
    user_id = data.get('user_id')
    event_id = data.get('event_id')
    captcha = data.get('captcha')
    captcha_session = data.get('captcha_session')
    
    # 1. 限流检查
    if not rate_limiter.allow(f"reg:{user_id}"):
        return jsonify({'success': False, 'message': '请求过于频繁，请稍后重试'}), 429
    
    # 2. 验证码检查
    if not captcha_service.verify(captcha_session, captcha):
        return jsonify({'success': False, 'message': '验证码错误或已过期'}), 400
    
    # 3. 检查名额（模拟Redis预扣）
    quota_key = f"quota:{event_id}"
    remaining = cache.get(quota_key)
    
    conn = get_db()
    if remaining is None:
        event = conn.execute('SELECT max_participants, current_participants FROM event WHERE id = ?', (event_id,)).fetchone()
        if not event:
            conn.close()
            return jsonify({'success': False, 'message': '活动不存在'}), 404
        remaining = event['max_participants'] - event['current_participants']
        cache.set(quota_key, remaining, ttl=3600)
    
    if remaining <= 0:
        conn.close()
        return jsonify({'success': False, 'message': '名额已满'}), 400
    
    # 4. 预扣名额
    new_remaining = cache.decr(quota_key)
    if new_remaining < 0:
        cache.incr(quota_key)
        conn.close()
        return jsonify({'success': False, 'message': '名额已满'}), 400
    
    # 5. 写入数据库
    try:
        conn.execute('INSERT INTO registration (event_id, user_id) VALUES (?, ?)', (event_id, user_id))
        conn.execute('UPDATE event SET current_participants = current_participants + 1 WHERE id = ?', (event_id,))
        conn.commit()
        cache.delete(f'event:{event_id}')  # 清除缓存
        return jsonify({'success': True, 'message': '报名成功'})
    except sqlite3.IntegrityError:
        cache.incr(quota_key)  # 回滚名额
        return jsonify({'success': False, 'message': '您已报名该活动'}), 400
    finally:
        conn.close()

@app.route('/api/registration/list', methods=['GET'])
def list_registrations():
    """获取用户报名列表"""
    user_id = request.args.get('user_id')
    conn = get_db()
    registrations = conn.execute('''
        SELECT r.id, r.event_id, r.status, r.registered_at, e.title, e.start_time, e.location
        FROM registration r JOIN event e ON r.event_id = e.id
        WHERE r.user_id = ? ORDER BY r.registered_at DESC
    ''', (user_id,)).fetchall()
    conn.close()
    return jsonify({'success': True, 'registrations': [dict(r) for r in registrations]})

@app.route('/api/registration/cancel', methods=['POST'])
def cancel_registration():
    """取消报名"""
    data = request.json
    conn = get_db()
    result = conn.execute('DELETE FROM registration WHERE event_id = ? AND user_id = ?',
                         (data['event_id'], data['user_id']))
    if result.rowcount > 0:
        conn.execute('UPDATE event SET current_participants = current_participants - 1 WHERE id = ?', (data['event_id'],))
        cache.incr(f"quota:{data['event_id']}")
        cache.delete(f"event:{data['event_id']}")
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': '取消成功'})

# ==================== 根路径 ====================
@app.route('/', methods=['GET'])
def index():
    """根路径欢迎页"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>校园活动报名系统 API</title>
        <meta charset="utf-8">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Microsoft YaHei', sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                max-width: 500px;
                width: 90%;
                text-align: center;
            }
            .logo { font-size: 60px; margin-bottom: 10px; }
            h1 { color: #333; font-size: 24px; margin-bottom: 10px; }
            .status { 
                display: inline-block;
                background: #d4edda; 
                color: #155724; 
                padding: 5px 15px; 
                border-radius: 20px; 
                font-size: 14px;
                margin: 15px 0;
            }
            .status::before { content: "● "; }
            .api-list { 
                text-align: left; 
                background: #f8f9fa; 
                padding: 20px; 
                border-radius: 10px; 
                margin: 20px 0;
            }
            .api-list h3 { color: #555; font-size: 14px; margin-bottom: 15px; }
            .api-item { 
                display: flex; 
                justify-content: space-between; 
                padding: 10px 0; 
                border-bottom: 1px solid #eee;
            }
            .api-item:last-child { border-bottom: none; }
            .api-item a { 
                color: #667eea; 
                text-decoration: none; 
                font-family: monospace;
                font-size: 13px;
            }
            .api-item a:hover { text-decoration: underline; }
            .api-item span { color: #888; font-size: 13px; }
            .tip { 
                background: #fff3cd; 
                color: #856404; 
                padding: 15px; 
                border-radius: 8px; 
                font-size: 13px;
                margin-top: 15px;
            }
            .tip code { 
                background: #ffeeba; 
                padding: 2px 6px; 
                border-radius: 3px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">🎓</div>
            <h1>校园活动报名系统</h1>
            <p style="color: #888;">高并发Web架构设计 Demo</p>
            <div class="status">服务运行正常</div>
            
            <div class="api-list">
                <h3>📡 API 接口</h3>
                <div class="api-item">
                    <a href="/api/event/list">/api/event/list</a>
                    <span>活动列表</span>
                </div>
                <div class="api-item">
                    <a href="/api/health">/api/health</a>
                    <span>健康检查</span>
                </div>
                <div class="api-item">
                    <a href="/api/metrics">/api/metrics</a>
                    <span>系统指标</span>
                </div>
            </div>
            
            <div class="tip">
                💡 请打开 <code>frontend/index.html</code> 使用完整功能
            </div>
        </div>
    </body>
    </html>
    '''

# ==================== 系统监控API ====================
@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """获取系统指标 - 模拟Prometheus指标"""
    return jsonify({
        'http_requests_total': random.randint(1000, 5000),
        'http_request_duration_seconds': round(random.uniform(0.01, 0.5), 3),
        'active_connections': random.randint(10, 100),
        'cache_hit_rate': round(random.uniform(0.7, 0.95), 2),
        'db_connections': random.randint(5, 20)
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

# ==================== 初始化测试数据 ====================
def init_test_data():
    """初始化测试数据"""
    conn = get_db()
    
    # 检查是否已有数据
    count = conn.execute('SELECT COUNT(*) FROM event').fetchone()[0]
    if count > 0:
        conn.close()
        return
    
    # 添加测试用户
    users = [
        ('2021001', '张三', hashlib.sha256('123456'.encode()).hexdigest(), 1, 'zhangsan@edu.cn', '13800001111'),
        ('2021002', '李四', hashlib.sha256('123456'.encode()).hexdigest(), 2, 'lisi@edu.cn', '13800002222'),
        ('2021003', '王五', hashlib.sha256('123456'.encode()).hexdigest(), 1, 'wangwu@edu.cn', '13800003333'),
        ('2021004', '赵六', hashlib.sha256('123456'.encode()).hexdigest(), 3, 'zhaoliu@edu.cn', '13800004444'),
        ('2021005', '钱七', hashlib.sha256('123456'.encode()).hexdigest(), 4, 'qianqi@edu.cn', '13800005555'),
    ]
    conn.executemany('INSERT OR IGNORE INTO user (student_id, username, password_hash, college_id, email, phone) VALUES (?, ?, ?, ?, ?, ?)', users)
    
    # 添加测试活动
    now = datetime.now()
    events = [
        ('2024年校园歌手大赛', '展示你的歌唱才华，赢取丰厚奖品！一等奖3000元，二等奖2000元，三等奖1000元。', 1, 1, '大学生活动中心',
         (now + timedelta(days=7)).strftime('%Y-%m-%d 19:00:00'),
         (now + timedelta(days=7)).strftime('%Y-%m-%d 22:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=5)).strftime('%Y-%m-%d 23:59:59'), 100),
        ('Python编程工作坊', '学习Python基础，动手实践项目开发。适合零基础同学，提供免费教材。', 1, 2, '计算机学院实验室301',
         (now + timedelta(days=3)).strftime('%Y-%m-%d 14:00:00'),
         (now + timedelta(days=3)).strftime('%Y-%m-%d 17:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=2)).strftime('%Y-%m-%d 23:59:59'), 50),
        ('校园马拉松', '挑战自我，跑出健康！全程5公里，完赛即可获得纪念奖牌。', 1, None, '校园操场',
         (now + timedelta(days=14)).strftime('%Y-%m-%d 07:00:00'),
         (now + timedelta(days=14)).strftime('%Y-%m-%d 12:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=10)).strftime('%Y-%m-%d 23:59:59'), 500),
        ('创业分享会', '听成功创业者分享经验，了解创业路上的机遇与挑战。', 1, 3, '商学院报告厅',
         (now + timedelta(days=5)).strftime('%Y-%m-%d 15:00:00'),
         (now + timedelta(days=5)).strftime('%Y-%m-%d 17:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=4)).strftime('%Y-%m-%d 23:59:59'), 200),
        ('英语角活动', '与外教面对面交流，提升口语能力。每周三下午定期举办。', 1, 3, '外语学院咖啡厅',
         (now + timedelta(days=2)).strftime('%Y-%m-%d 16:00:00'),
         (now + timedelta(days=2)).strftime('%Y-%m-%d 18:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=1)).strftime('%Y-%m-%d 23:59:59'), 30),
        ('摄影技巧讲座', '专业摄影师教你手机摄影技巧，拍出大片感！', 1, 1, '艺术楼多媒体教室',
         (now + timedelta(days=6)).strftime('%Y-%m-%d 14:00:00'),
         (now + timedelta(days=6)).strftime('%Y-%m-%d 16:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=5)).strftime('%Y-%m-%d 23:59:59'), 80),
        ('篮球友谊赛', '各学院篮球队友谊赛，欢迎同学们来观赛助威！', 1, None, '体育馆篮球场',
         (now + timedelta(days=8)).strftime('%Y-%m-%d 15:00:00'),
         (now + timedelta(days=8)).strftime('%Y-%m-%d 18:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=7)).strftime('%Y-%m-%d 23:59:59'), 300),
        ('读书分享会', '分享你最近读的好书，与书友交流心得。', 1, 3, '图书馆报告厅',
         (now + timedelta(days=4)).strftime('%Y-%m-%d 19:00:00'),
         (now + timedelta(days=4)).strftime('%Y-%m-%d 21:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=3)).strftime('%Y-%m-%d 23:59:59'), 60),
        ('AI技术前沿讲座', '了解人工智能最新发展，探索未来科技趋势。', 1, 2, '计算机学院报告厅',
         (now + timedelta(days=10)).strftime('%Y-%m-%d 14:00:00'),
         (now + timedelta(days=10)).strftime('%Y-%m-%d 17:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=8)).strftime('%Y-%m-%d 23:59:59'), 150),
        ('志愿者招募', '参与社区服务，奉献爱心，获得志愿时长认证。', 1, None, '学生活动中心',
         (now + timedelta(days=9)).strftime('%Y-%m-%d 09:00:00'),
         (now + timedelta(days=9)).strftime('%Y-%m-%d 12:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=7)).strftime('%Y-%m-%d 23:59:59'), 100),
        ('新年晚会', '辞旧迎新，精彩节目轮番上演，还有抽奖环节！', 1, None, '大礼堂',
         (now + timedelta(days=20)).strftime('%Y-%m-%d 19:00:00'),
         (now + timedelta(days=20)).strftime('%Y-%m-%d 22:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=18)).strftime('%Y-%m-%d 23:59:59'), 800),
        ('职业规划讲座', '资深HR教你如何规划职业生涯，简历制作技巧。', 1, 2, '就业指导中心',
         (now + timedelta(days=11)).strftime('%Y-%m-%d 14:00:00'),
         (now + timedelta(days=11)).strftime('%Y-%m-%d 16:00:00'),
         now.strftime('%Y-%m-%d 00:00:00'),
         (now + timedelta(days=9)).strftime('%Y-%m-%d 23:59:59'), 120),
    ]
    conn.executemany('''INSERT INTO event (title, description, organizer_id, college_id, location,
                        start_time, end_time, registration_start, registration_end, max_participants)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', events)
    
    conn.commit()
    conn.close()
    print("测试数据初始化完成")

# ==================== 启动应用 ====================
if __name__ == '__main__':
    init_db()
    init_test_data()
    print("=" * 50)
    print("校园活动报名系统启动")
    print("API地址: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, port=5000)
