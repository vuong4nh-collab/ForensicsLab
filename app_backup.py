from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, hashlib, os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'forensicslab2026'
DB = 'forensicslab.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'student',
            fullname TEXT
        );
        CREATE TABLE IF NOT EXISTS scenarios (
            id INTEGER PRIMARY KEY,
            title TEXT,
            description TEXT,
            level TEXT,
            tools TEXT,
            duration TEXT,
            status TEXT DEFAULT 'locked'
        );
        CREATE TABLE IF NOT EXISTS progress (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            scenario_id INTEGER,
            status TEXT DEFAULT 'not_started',
            score REAL,
            submitted_at TEXT,
            report TEXT
        );
    ''')
    # Seed data
    pw_admin = hashlib.sha256('admin123'.encode()).hexdigest()
    pw_sv = hashlib.sha256('kali'.encode()).hexdigest()
    try:
        conn.execute("INSERT INTO users (username,password,role,fullname) VALUES (?,?,?,?)",
                     ('giaovien@haui.edu.vn', pw_admin, 'teacher', 'Th. Nguyễn An'))
        conn.execute("INSERT INTO users (username,password,role,fullname) VALUES (?,?,?,?)",
                     ('sinhvien@haui.edu.vn', pw_sv, 'student', 'Nguyễn Minh Vương'))
        conn.executemany("INSERT INTO scenarios (title,description,level,tools,duration,status) VALUES (?,?,?,?,?,?)", [
            ('Network Forensics','Phân tích lưu lượng mạng, phát hiện tấn công SQL Injection và Brute Force','Cơ bản','Wireshark','45 phút','active'),
            ('Disk Forensics','Điều tra ổ cứng, khôi phục file đã xóa và phát hiện malware','Trung bình','Autopsy · FTK Imager','90 phút','active'),
            ('Memory Forensics','Phân tích RAM dump, phát hiện tiến trình ẩn','Nâng cao','Volatility 3','120 phút','active'),
            ('Tổng hợp','Kịch bản tích hợp toàn bộ kỹ năng forensics','Nâng cao','Tất cả công cụ','180 phút','locked'),
        ])
        conn.commit()
    except:
        pass
    conn.close()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password)).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['fullname'] = user['fullname']
            return redirect(url_for('dashboard'))
        error = 'Tên đăng nhập hoặc mật khẩu không đúng'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    scenarios = conn.execute("SELECT * FROM scenarios").fetchall()
    if session['role'] == 'student':
        progress = conn.execute("SELECT * FROM progress WHERE user_id=?", (session['user_id'],)).fetchall()
        progress_map = {p['scenario_id']: p for p in progress}
        conn.close()
        return render_template('student_dashboard.html', scenarios=scenarios, progress_map=progress_map)
    else:
        students = conn.execute("SELECT * FROM users WHERE role='student'").fetchall()
        all_progress = conn.execute("SELECT p.*, u.fullname, s.title FROM progress p JOIN users u ON p.user_id=u.id JOIN scenarios s ON p.scenario_id=s.id").fetchall()
        conn.close()
        return render_template('teacher_dashboard.html', scenarios=scenarios, students=students, all_progress=all_progress)

@app.route('/lab/<int:scenario_id>')
def lab(scenario_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    scenario = conn.execute("SELECT * FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
    progress = conn.execute("SELECT * FROM progress WHERE user_id=? AND scenario_id=?",
                            (session['user_id'], scenario_id)).fetchone()
    conn.close()
    return render_template('lab.html', scenario=scenario, progress=progress)

@app.route('/submit_report/<int:scenario_id>', methods=['POST'])
def submit_report(scenario_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    report = request.form.get('report', '')
    conn = get_db()
    existing = conn.execute("SELECT * FROM progress WHERE user_id=? AND scenario_id=?",
                            (session['user_id'], scenario_id)).fetchone()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if existing:
        conn.execute("UPDATE progress SET report=?, status='submitted', submitted_at=? WHERE user_id=? AND scenario_id=?",
                     (report, now, session['user_id'], scenario_id))
    else:
        conn.execute("INSERT INTO progress (user_id,scenario_id,status,report,submitted_at) VALUES (?,?,'submitted',?,?)",
                     (session['user_id'], scenario_id, report, now))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/grade/<int:progress_id>', methods=['POST'])
def grade(progress_id):
    if session.get('role') != 'teacher':
        return redirect(url_for('dashboard'))
    score = request.form.get('score')
    conn = get_db()
    conn.execute("UPDATE progress SET score=?, status='graded' WHERE id=?", (score, progress_id))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
