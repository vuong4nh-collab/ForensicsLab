from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, g, send_from_directory
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, logging, hashlib, json, io, struct
from datetime import datetime
import sandbox_manager

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

csrf = CSRFProtect(app)

DB = 'forensicslab.db'
EVIDENCE_BASE = os.path.join(os.path.dirname(__file__), 'static', 'evidence')
HEX_PREVIEW_BYTES = 512
logging.basicConfig(level=logging.INFO)

# ─── Dynamic Scenario 3 (Memory Forensics) helpers ──────────────────────────

# Predefined pools for deterministic randomisation per user
_C2_IP_POOL = [
    '185.220.101.5', '91.108.4.50', '194.165.16.10',
    '45.142.212.100', '176.10.104.240', '198.96.155.3',
]
_PORT_POOL = [4444, 5555, 8080, 9001, 1337, 6666]
_PID_POOL  = [3824, 2844, 4812, 3120, 5032, 2196]


def get_dynamic_scenario3_values(user_id: int) -> dict:
    """Return deterministic per-student values for Scenario 3.

    Uses user_id as the index seed so the same student always gets
    the same PID / C2 IP / port / flag combination, but different
    students get different values — preventing answer sharing.
    """
    idx  = int(user_id) % len(_C2_IP_POOL)
    pid  = _PID_POOL[idx]
    ip   = _C2_IP_POOL[idx]
    port = _PORT_POOL[idx]
    flag = f'FLAG{{m3m_{hashlib.md5(f"s3u{user_id}".encode()).hexdigest()[:8]}}}'
    return {
        'pid':    pid,
        'c2_ip':  ip,
        'port':   port,
        'c2':     f'{ip}:{port}',
        'flag':   flag,
    }


def build_dynamic_vmem(user_id: int) -> bytes:
    """Load the static memory_dump.vmem and patch it with per-student
    values so the binary evidence matches the dynamic answers.
    """
    static_path = os.path.join(EVIDENCE_BASE, 'scenario_3', 'memory_dump.vmem')
    v = get_dynamic_scenario3_values(user_id)

    try:
        with open(static_path, 'rb') as f:
            mem = bytearray(f.read())
    except FileNotFoundError:
        # Fallback: generate a minimal 2 MB skeleton on-the-fly
        mem = bytearray(2 * 1024 * 1024)

    def _patch(offset: int, data: bytes):
        end = offset + len(data)
        if end <= len(mem):
            mem[offset:end] = data
        else:
            # Extend if base file is smaller than expected
            mem.extend(b'\x00' * (end - len(mem)))
            mem[offset:end] = data

    pid_str = str(v['pid']).encode()
    c2_str  = v['c2'].encode()
    flag_b  = f'FOUND FLAG IN RAM: {v["flag"]}'.encode()

    # Patch process-list region (offset 0x1000)
    proc = (
        b'System\x004\x00'
        b'services.exe\x001024\x00'
        b'svchost.exe\x003920\x00'
        b'svchost_malicious.exe\x00' + pid_str + b'\x00'
        b'C:\\Windows\\Temp\\svchost_malicious.exe\x00'
        b'explorer.exe\x002180\x00'
    )
    _patch(0x1000, proc)

    # Patch network-connection region (offset 0x5000)
    net = (
        b'ESTABLISHED\x00192.168.1.10:49210\x00' + c2_str + b'\x00' + pid_str + b'\x00'
        b'LISTENING\x00192.168.1.10:135\x000.0.0.0:0\x00820\x00'
    )
    _patch(0x5000, net)

    # Patch C2/flag region (offset 0x8ff0)
    c2_block = (
        b'GET /commands HTTP/1.1\x00'
        b'Host: ' + v['c2_ip'].encode() + b'\x00'
        b'C2 Connection established. Shell spawned.\x00'
        + flag_b + b'\x00'
    )
    _patch(0x8ff0, c2_block)

    return bytes(mem)

# ─── DB helpers ─────────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON;")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
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
                score REAL DEFAULT 0.0,
                teacher_score REAL DEFAULT 0.0,
                submitted_at TEXT,
                report TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (scenario_id) REFERENCES scenarios(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY,
                scenario_id INTEGER,
                question_text TEXT,
                correct_flag TEXT,
                points REAL,
                hint TEXT,
                FOREIGN KEY (scenario_id) REFERENCES scenarios(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS user_answers (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                scenario_id INTEGER,
                question_id INTEGER,
                submitted_flag TEXT,
                is_correct INTEGER DEFAULT 0,
                submitted_at TEXT,
                mode TEXT DEFAULT 'simulated',
                points_earned REAL DEFAULT 0.0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (scenario_id) REFERENCES scenarios(id) ON DELETE CASCADE,
                FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
                UNIQUE(user_id, question_id)
            );
            CREATE TABLE IF NOT EXISTS evidence_files (
                id INTEGER PRIMARY KEY,
                scenario_id INTEGER,
                filename TEXT,
                filepath TEXT,
                sha256 TEXT,
                size INTEGER,
                file_type TEXT,
                description TEXT,
                uploaded_at TEXT,
                uploaded_by INTEGER,
                FOREIGN KEY (scenario_id) REFERENCES scenarios(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS evidence_access_log (
                id INTEGER PRIMARY KEY,
                evidence_id INTEGER,
                user_id INTEGER,
                action TEXT,
                accessed_at TEXT,
                ip_address TEXT,
                FOREIGN KEY (evidence_id) REFERENCES evidence_files(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS sandboxes (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                scenario_id INTEGER,
                container_id TEXT,
                status TEXT DEFAULT 'stopped',
                started_at TEXT,
                last_active TEXT,
                UNIQUE(user_id, scenario_id)
            );
            CREATE TABLE IF NOT EXISTS sandbox_command_log (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                scenario_id INTEGER,
                command TEXT,
                executed_at TEXT,
                ip_address TEXT,
                exit_code INTEGER,
                mode TEXT DEFAULT 'simulated',
                output_snippet TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (scenario_id) REFERENCES scenarios(id) ON DELETE CASCADE
            );
        ''')

        # Schema migrations for older DBs
        for col_def in [
            ("progress", "teacher_score REAL DEFAULT 0.0"),
            ("sandbox_command_log", "mode TEXT DEFAULT 'simulated'"),
            ("sandbox_command_log", "output_snippet TEXT"),
            ("user_answers", "mode TEXT DEFAULT 'simulated'"),
            ("user_answers", "points_earned REAL DEFAULT 0.0"),
        ]:
            try:
                conn.execute(f"ALTER TABLE {col_def[0]} ADD COLUMN {col_def[1]};")
            except sqlite3.OperationalError:
                pass

        # Backfill points_earned for older records that are correct but have 0.0 points
        try:
            conn.execute("""
                UPDATE user_answers
                SET points_earned = (SELECT points FROM questions WHERE questions.id = user_answers.question_id)
                WHERE points_earned = 0.0 AND is_correct = 1
            """)
            conn.commit()
        except sqlite3.Error:
            pass

        # Seed users
        pw_admin = generate_password_hash('admin123')
        pw_sv = generate_password_hash('kali')
        try:
            conn.execute("INSERT INTO users (username,password,role,fullname) VALUES (?,?,?,?)",
                         ('giaovien@haui.edu.vn', pw_admin, 'teacher', 'Th. Nguyễn An'))
            conn.execute("INSERT INTO users (username,password,role,fullname) VALUES (?,?,?,?)",
                         ('sinhvien@haui.edu.vn', pw_sv, 'student', 'Nguyễn Minh Vương'))
            conn.executemany("INSERT INTO scenarios (title,description,level,tools,duration,status) VALUES (?,?,?,?,?,?)", [
                ('Network Forensics','Phân tích lưu lượng mạng, phát hiện tấn công SQL Injection và Brute Force','Cơ bản','Wireshark/tshark CLI','45 phút','active'),
                ('Disk Forensics','Điều tra ổ cứng, khôi phục file đã xóa và phát hiện malware','Trung bình','Autopsy workflow · SleuthKit · libewf','90 phút','active'),
                ('Memory Forensics','Phân tích RAM dump, phát hiện tiến trình ẩn','Nâng cao','Volatility 3 (vol)','120 phút','active'),
                ('Tổng hợp','Kịch bản tích hợp toàn bộ kỹ năng forensics','Nâng cao','Tất cả công cụ','180 phút','locked'),
            ])
            conn.commit()
        except sqlite3.IntegrityError:
            logging.info('Seed data already exists.')

        # Keep legacy databases aligned with the Docker CLI toolchain.
        conn.executemany("UPDATE scenarios SET tools=? WHERE id=? AND tools=?", [
            ('Wireshark/tshark CLI', 1, 'Wireshark · tshark'),
            ('Autopsy workflow · SleuthKit · libewf', 2, 'Autopsy · FTK Imager · sleuthkit'),
            ('Volatility 3 (vol)', 3, 'Volatility 3'),
        ])
        conn.commit()

        # Seed questions
        cursor = conn.execute("SELECT COUNT(*) FROM questions")
        if cursor.fetchone()[0] == 0:
            conn.executemany("INSERT INTO questions (scenario_id, question_text, correct_flag, points, hint) VALUES (?,?,?,?,?)", [
                (1, "Tìm địa chỉ IP nguồn thực hiện hành vi quét/tấn công brute force.", "192.168.1.105", 1.5, "Kiểm tra log các gói tin HTTP hoặc các gói tin TCP SYN ở console."),
                (1, "Xác định cổng/giao thức dịch vụ web bị tấn công nhiều nhất.", "80", 1.5, "Cổng dịch vụ Web phổ biến chạy qua giao thức HTTP."),
                (1, "Kiểu tấn công web nào được kẻ tấn công sử dụng để cố gắng trích xuất dữ liệu?", "SQL Injection", 1.5, "Kẻ tấn công sử dụng các ký tự đặc biệt như dấu nháy đơn, UNION SELECT..."),
                (1, "Giá trị flag bí mật ẩn trong nội dung phản hồi HTTP GET là gì?", "FLAG{wire_sh4rk_rules}", 1.5, "Lọc theo giao thức http và xem các phản hồi 200 OK."),
                (2, "Mã hash MD5 của tệp ảnh ổ cứng suspect_disk.E01 là gì?", "dab05fdce91ee2ff2de2269c837e77b8", 2.0, "Dùng lệnh md5sum trên tệp tin ảnh ổ cứng."),
                (2, "Tên tệp tin bị xóa chứa thông tin nhạy cảm của hacker là gì?", "secret_flag.txt", 2.0, "Dùng strings hoặc fls để tìm dấu vết tệp đã bị xóa trong ảnh đĩa."),
                (2, "Giá trị flag bí mật được lưu trữ trong tệp bị xóa đó là gì?", "FLAG{d1sk_f0r3ns1cs_is_fun}", 2.0, "Dùng strings hoặc icat để đọc nội dung tệp bị xóa theo dấu vết tìm được."),
                (3, "Tìm PID của tiến trình svchost giả mạo đang chạy ẩn trong hệ thống.", "3824", 2.0, "Dùng vol -f memory_dump.vmem windows.pslist hoặc strings để tìm tiến trình svchost đáng ngờ."),
                (3, "Địa chỉ IP và Port (dạng IP:Port) mà tiến trình độc hại kết nối tới để nhận lệnh?", "185.220.101.5:4444", 2.0, "Dùng vol -f memory_dump.vmem windows.netscan hoặc strings để tìm kết nối ESTABLISHED."),
                (3, "Flag bí mật tìm thấy trong vùng nhớ strings của tiến trình độc hại là gì?", "FLAG{m3m0ry_4n4lys1s_pr0}", 2.0, "Dùng strings memory_dump.vmem hoặc plugin strings tương ứng để tìm chuỗi FLAG."),
            ])
            conn.commit()
            logging.info('Questions seeded.')

        disk_evidence_path = os.path.join(EVIDENCE_BASE, 'scenario_2', 'suspect_disk.E01')
        if os.path.exists(disk_evidence_path):
            md5 = hashlib.md5()
            with open(disk_evidence_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5.update(chunk)
            conn.execute(
                "UPDATE questions SET correct_flag=? WHERE scenario_id=2 AND question_text LIKE ?",
                (md5.hexdigest(), '%MD5%')
            )
        conn.execute(
            "UPDATE questions SET hint=? WHERE scenario_id=2 AND correct_flag=?",
            ("Dùng strings hoặc fls để tìm dấu vết tệp đã bị xóa trong ảnh đĩa.", "secret_flag.txt")
        )
        conn.execute(
            "UPDATE questions SET hint=? WHERE scenario_id=2 AND correct_flag=?",
            ("Dùng strings hoặc icat để đọc nội dung tệp bị xóa theo dấu vết tìm được.", "FLAG{d1sk_f0r3ns1cs_is_fun}")
        )
        conn.execute(
            "UPDATE questions SET hint=? WHERE scenario_id=3 AND correct_flag=?",
            ("Dùng vol -f memory_dump.vmem windows.pslist hoặc strings để tìm tiến trình svchost đáng ngờ.", "3824")
        )
        conn.execute(
            "UPDATE questions SET hint=? WHERE scenario_id=3 AND correct_flag=?",
            ("Dùng vol -f memory_dump.vmem windows.netscan hoặc strings để tìm kết nối ESTABLISHED.", "185.220.101.5:4444")
        )
        conn.execute(
            "UPDATE questions SET hint=? WHERE scenario_id=3 AND correct_flag=?",
            ("Dùng strings memory_dump.vmem hoặc plugin strings tương ứng để tìm chuỗi FLAG.", "FLAG{m3m0ry_4n4lys1s_pr0}")
        )
        conn.commit()

        # Seed evidence files from manifest
        ev_count = conn.execute("SELECT COUNT(*) FROM evidence_files").fetchone()[0]
        if ev_count == 0:
            manifest_path = os.path.join(EVIDENCE_BASE, 'manifest.json')
            if os.path.exists(manifest_path):
                with open(manifest_path) as f:
                    manifest = json.load(f)
                for item in manifest:
                    fname = item['filename']
                    spath = f"scenario_{item['scenario_id']}"
                    fpath = os.path.join(spath, fname)
                    ext = fname.rsplit('.', 1)[-1].lower() if '.' in fname else 'bin'
                    desc_map = {
                        'pcapng': 'File chụp lưu lượng mạng (Packet Capture)',
                        'e01': 'Ảnh ổ cứng định dạng Expert Witness (EnCase)',
                        'vmem': 'Memory dump VMware (RAM Dump)',
                        'txt': 'Tệp văn bản',
                        'sha256': 'Checksum SHA-256',
                    }
                    conn.execute(
                        "INSERT INTO evidence_files (scenario_id,filename,filepath,sha256,size,file_type,description,uploaded_at,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?)",
                        (item['scenario_id'], fname, fpath, item['sha256'], item['size'],
                         ext, desc_map.get(ext, 'Tệp chứng cứ số'),
                         item['generated_at'], 1)
                    )
                conn.commit()
                logging.info('Evidence files seeded from manifest.')


def get_scenario(conn, scenario_id):
    return conn.execute("SELECT * FROM scenarios WHERE id=?", (scenario_id,)).fetchone()


def user_can_access_scenario(scenario):
    return bool(scenario) and (
        session.get('role') == 'teacher' or scenario['status'] != 'locked'
    )


def get_evidence_record(conn, file_id):
    return conn.execute("""
        SELECT ef.*, s.status AS scenario_status
        FROM evidence_files ef
        JOIN scenarios s ON s.id = ef.scenario_id
        WHERE ef.id=?
    """, (file_id,)).fetchone()


def resolve_evidence_path(filepath):
    base_path = os.path.abspath(EVIDENCE_BASE)
    candidate = os.path.abspath(os.path.join(EVIDENCE_BASE, filepath))
    if os.path.commonpath([base_path, candidate]) != base_path:
        raise ValueError('Invalid evidence path')
    return candidate

# ─── Auth ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and not check_password_hash(user['password'], password):
            user = None
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
    # Stop sandbox if running
    if 'user_id' in session:
        try:
            conn = get_db()
            sandboxes = conn.execute("SELECT scenario_id FROM sandboxes WHERE user_id=? AND status='running'",
                                     (session['user_id'],)).fetchall()
            for sb in sandboxes:
                sandbox_manager.stop_sandbox(session['user_id'], sb['scenario_id'])
        except Exception:
            pass
    session.clear()
    return redirect(url_for('login'))

# ─── Dashboard ───────────────────────────────────────────────────────────────

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    scenarios = conn.execute("SELECT * FROM scenarios").fetchall()
    if session['role'] == 'student':
        progress = conn.execute("SELECT * FROM progress WHERE user_id=?", (session['user_id'],)).fetchall()
        progress_map = {p['scenario_id']: p for p in progress}
        solved_flags = conn.execute("SELECT COUNT(*) FROM user_answers WHERE user_id=? AND is_correct=1", (session['user_id'],)).fetchone()[0]
        total_flags = conn.execute("SELECT COUNT(*) FROM questions").fetchone()[0]
        return render_template('student_dashboard.html', scenarios=scenarios, progress_map=progress_map,
                               solved_flags=solved_flags, total_flags=total_flags)
    else:
        students = conn.execute("SELECT * FROM users WHERE role='student'").fetchall()
        all_progress = conn.execute("""
            SELECT p.*, u.fullname, s.title,
                   (SELECT COUNT(*) FROM user_answers ua WHERE ua.user_id = p.user_id AND ua.scenario_id = p.scenario_id AND ua.is_correct = 1) as correct_flags,
                   (SELECT COUNT(*) FROM questions q WHERE q.scenario_id = p.scenario_id) as total_flags
            FROM progress p
            JOIN users u ON p.user_id=u.id
            JOIN scenarios s ON p.scenario_id=s.id
        """).fetchall()

        command_logs = conn.execute("""
            SELECT scl.*, u.fullname, s.title as scenario_title
            FROM sandbox_command_log scl
            JOIN users u ON scl.user_id = u.id
            JOIN scenarios s ON scl.scenario_id = s.id
            ORDER BY scl.executed_at DESC
            LIMIT 100
        """).fetchall()

        return render_template('teacher_dashboard.html', scenarios=scenarios, students=students,
                               all_progress=all_progress, command_logs=command_logs)



# ─── Lab ─────────────────────────────────────────────────────────────────────

@app.route('/lab/<int:scenario_id>')
def lab(scenario_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    scenario = get_scenario(conn, scenario_id)
    if not scenario:
        abort(404)
    if not user_can_access_scenario(scenario):
        abort(403)
    progress = conn.execute("SELECT * FROM progress WHERE user_id=? AND scenario_id=?",
                            (session['user_id'], scenario_id)).fetchone()
    questions = conn.execute("""
        SELECT q.id, q.question_text, q.points, q.hint,
               ua.submitted_flag, ua.is_correct, ua.submitted_at
        FROM questions q
        LEFT JOIN user_answers ua ON q.id = ua.question_id AND ua.user_id = ?
        WHERE q.scenario_id = ?
        ORDER BY q.id ASC
    """, (session['user_id'], scenario_id)).fetchall()

    # Evidence files for this scenario
    evidence_files = conn.execute(
        "SELECT * FROM evidence_files WHERE scenario_id=? ORDER BY id",
        (scenario_id,)).fetchall()

    # Sandbox status
    sandbox_status = sandbox_manager.get_sandbox_status(session['user_id'], scenario_id)
    docker_available = sandbox_manager.is_docker_available()
    image_ready = sandbox_manager.is_image_available()

    # Dynamic per-student values for Scenario 3
    dynamic_values = None
    if scenario_id == 3:
        dynamic_values = get_dynamic_scenario3_values(session['user_id'])

    return render_template('lab.html',
                           scenario=scenario,
                           progress=progress,
                           questions=questions,
                           evidence_files=evidence_files,
                           sandbox_status=sandbox_status,
                           docker_available=docker_available,
                           image_ready=image_ready,
                           dynamic_values=dynamic_values)


@app.route('/api/questions/<int:scenario_id>')
def api_questions(scenario_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    scenario = get_scenario(conn, scenario_id)
    if not scenario:
        return jsonify({'error': 'Scenario not found'}), 404
    if not user_can_access_scenario(scenario):
        return jsonify({'error': 'Forbidden'}), 403

    questions = conn.execute("""
        SELECT q.id, q.question_text, q.points, q.hint,
               ua.submitted_flag, ua.is_correct, ua.submitted_at
        FROM questions q
        LEFT JOIN user_answers ua ON q.id = ua.question_id AND ua.user_id = ?
        WHERE q.scenario_id = ?
        ORDER BY q.id ASC
    """, (session['user_id'], scenario_id)).fetchall()

    payload = []
    total_points = 0.0
    earned_points = 0.0
    solved_questions = 0
    for question in questions:
        item = dict(question)
        item['is_correct'] = bool(item['is_correct'])
        payload.append(item)
        total_points += question['points'] or 0.0
        if item['is_correct']:
            earned_points += question['points'] or 0.0
            solved_questions += 1

    return jsonify({
        'scenario_id': scenario_id,
        'total_questions': len(payload),
        'solved_questions': solved_questions,
        'total_points': total_points,
        'earned_points': earned_points,
        'questions': payload,
    })

# ─── Evidence APIs ────────────────────────────────────────────────────────────

@app.route('/api/evidence/<int:scenario_id>')
def api_evidence_list(scenario_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    scenario = get_scenario(conn, scenario_id)
    if not scenario:
        return jsonify({'error': 'Scenario not found'}), 404
    if not user_can_access_scenario(scenario):
        return jsonify({'error': 'Forbidden'}), 403
    files = conn.execute(
        "SELECT id,filename,sha256,size,file_type,description,uploaded_at FROM evidence_files WHERE scenario_id=?",
        (scenario_id,)).fetchall()
    return jsonify([dict(f) for f in files])


@app.route('/api/evidence/verify/<int:file_id>')
def api_evidence_verify(file_id):
    """Real-time SHA-256 integrity check."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    ev = get_evidence_record(conn, file_id)
    if not ev:
        return jsonify({'ok': False, 'message': 'File không tồn tại trong DB'}), 404
    if session.get('role') != 'teacher' and ev['scenario_status'] == 'locked':
        return jsonify({'error': 'Forbidden'}), 403

    # For Scenario 3 vmem: hash the dynamic patched content instead of static file
    is_dynamic_vmem = (ev['scenario_id'] == 3 and ev['file_type'] == 'vmem')

    if is_dynamic_vmem:
        data = build_dynamic_vmem(session['user_id'])
        actual = hashlib.sha256(data).hexdigest()
        # We always treat the dynamic file as intact (it's generated fresh)
        intact = True
        stored = actual
    else:
        try:
            fpath = resolve_evidence_path(ev['filepath'])
        except ValueError:
            return jsonify({'ok': False, 'message': 'Đường dẫn evidence không hợp lệ'}), 400
        if not os.path.exists(fpath):
            return jsonify({'ok': False, 'message': 'File không tồn tại trên server', 'stored_hash': ev['sha256']})

        h = hashlib.sha256()
        with open(fpath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        actual = h.hexdigest()
        stored = ev['sha256']
        intact = (actual == stored)

    # Log access
    conn.execute(
        "INSERT INTO evidence_access_log (evidence_id,user_id,action,accessed_at,ip_address) VALUES (?,?,?,?,?)",
        (file_id, session['user_id'], 'verify', datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
         request.remote_addr))
    conn.commit()

    return jsonify({
        'ok': intact,
        'intact': intact,
        'stored_hash': stored,
        'actual_hash': actual,
        'filename': ev['filename'],
        'message': 'Toàn vẹn xác nhận' if intact else 'CANH BAO: Hash khong khop! File co the bi thay doi!'
    })


@app.route('/api/evidence/hex/<int:file_id>')
def api_evidence_hex(file_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    ev = get_evidence_record(conn, file_id)
    if not ev:
        return jsonify({'error': 'Not found'}), 404
    if session.get('role') != 'teacher' and ev['scenario_status'] == 'locked':
        return jsonify({'error': 'Forbidden'}), 403

    try:
        fpath = resolve_evidence_path(ev['filepath'])
    except ValueError:
        return jsonify({'error': 'Invalid evidence path'}), 400
    if not os.path.exists(fpath):
        return jsonify({'error': 'Evidence file missing'}), 404

    with open(fpath, 'rb') as handle:
        data = handle.read(HEX_PREVIEW_BYTES)
    total_size = os.path.getsize(fpath)

    conn.execute(
        "INSERT INTO evidence_access_log (evidence_id,user_id,action,accessed_at,ip_address) VALUES (?,?,?,?,?)",
        (file_id, session['user_id'], 'inspect_hex', datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
         request.remote_addr))
    conn.commit()

    return jsonify({
        'filename': ev['filename'],
        'bytes': list(data),
        'preview_bytes': len(data),
        'total_size': total_size,
        'truncated': total_size > len(data),
    })


@app.route('/api/evidence/custody/<int:file_id>')
def api_evidence_custody(file_id):
    """Chain of custody log."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if session.get('role') != 'teacher':
        return jsonify({'error': 'Forbidden'}), 403
    conn = get_db()
    ev = get_evidence_record(conn, file_id)
    if not ev:
        return jsonify({'error': 'Not found'}), 404
    logs = conn.execute("""
        SELECT eal.action, eal.accessed_at, eal.ip_address, u.fullname, u.role
        FROM evidence_access_log eal
        JOIN users u ON eal.user_id = u.id
        WHERE eal.evidence_id = ?
        ORDER BY eal.accessed_at DESC
        LIMIT 20
    """, (file_id,)).fetchall()
    return jsonify({
        'filename': ev['filename'],
        'logs': [dict(l) for l in logs]
    })


@app.route('/api/evidence/download/<int:file_id>')
def api_evidence_download(file_id):
    """Download evidence file and log the access."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    ev = get_evidence_record(conn, file_id)
    if not ev:
        abort(404)
    if session.get('role') != 'teacher' and ev['scenario_status'] == 'locked':
        abort(403)

    # Log download
    conn.execute(
        "INSERT INTO evidence_access_log (evidence_id,user_id,action,accessed_at,ip_address) VALUES (?,?,?,?,?)",
        (file_id, session['user_id'], 'download', datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
         request.remote_addr))
    conn.commit()

    # For Scenario 3 vmem: serve the dynamically patched version
    if ev['scenario_id'] == 3 and ev['file_type'] == 'vmem':
        from flask import Response
        data = build_dynamic_vmem(session['user_id'])
        return Response(
            data,
            mimetype='application/octet-stream',
            headers={'Content-Disposition': 'attachment; filename="memory_dump.vmem"'}
        )

    try:
        fpath = resolve_evidence_path(ev['filepath'])
    except ValueError:
        abort(400)
    if not os.path.exists(fpath):
        abort(404)

    return send_from_directory(os.path.dirname(fpath), os.path.basename(fpath), as_attachment=True)

# ─── Sandbox APIs ─────────────────────────────────────────────────────────────

@app.route('/api/sandbox/status/<int:scenario_id>')
def api_sandbox_status(scenario_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    status = sandbox_manager.get_sandbox_status(session['user_id'], scenario_id)
    return jsonify(status)


@app.route('/api/sandbox/start/<int:scenario_id>', methods=['POST'])
def api_sandbox_start(scenario_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    success, message, container_id = sandbox_manager.start_sandbox(session['user_id'], scenario_id)
    if success:
        conn = get_db()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("""
            INSERT INTO sandboxes (user_id,scenario_id,container_id,status,started_at,last_active)
            VALUES (?,?,?,'running',?,?)
            ON CONFLICT(user_id,scenario_id) DO UPDATE SET
              container_id=excluded.container_id, status='running',
              started_at=excluded.started_at, last_active=excluded.last_active
        """, (session['user_id'], scenario_id, container_id or '', now, now))
        conn.commit()
    return jsonify({'success': success, 'message': message, 'container_id': container_id})


@app.route('/api/sandbox/stop/<int:scenario_id>', methods=['POST'])
def api_sandbox_stop(scenario_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    success, message = sandbox_manager.stop_sandbox(session['user_id'], scenario_id)
    if success:
        conn = get_db()
        conn.execute("UPDATE sandboxes SET status='stopped' WHERE user_id=? AND scenario_id=?",
                     (session['user_id'], scenario_id))
        conn.commit()
    return jsonify({'success': success, 'message': message})


@app.route('/api/sandbox/reset/<int:scenario_id>', methods=['POST'])
def api_sandbox_reset(scenario_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    success, message, container_id = sandbox_manager.reset_sandbox(session['user_id'], scenario_id)
    if success:
        conn = get_db()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("""
            INSERT INTO sandboxes (user_id,scenario_id,container_id,status,started_at,last_active)
            VALUES (?,?,?,'running',?,?)
            ON CONFLICT(user_id,scenario_id) DO UPDATE SET
              container_id=excluded.container_id, status='running',
              started_at=excluded.started_at, last_active=excluded.last_active
        """, (session['user_id'], scenario_id, container_id or '', now, now))
        conn.commit()
    return jsonify({'success': success, 'message': message})


@app.route('/api/sandbox/exec/<int:scenario_id>', methods=['POST'])
@csrf.exempt
def api_sandbox_exec(scenario_id):
    """Execute a command in the Docker sandbox."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json() or {}
    command = (data.get('command') or '').strip()
    if not command:
        return jsonify({'success': False, 'output': 'Lệnh rỗng.'})
    # Update last_active
    conn = get_db()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute("UPDATE sandboxes SET last_active=? WHERE user_id=? AND scenario_id=?",
                 (now_str, session['user_id'], scenario_id))
    conn.commit()
    success, output = sandbox_manager.exec_command(session['user_id'], scenario_id, command)

    # Log live Docker command
    try:
        snippet = (output or '')[:200].strip()
        conn.execute("""
            INSERT INTO sandbox_command_log (user_id, scenario_id, command, executed_at, ip_address, exit_code, mode, output_snippet)
            VALUES (?, ?, ?, ?, ?, ?, 'docker', ?)
        """, (session['user_id'], scenario_id, command, now_str, request.remote_addr,
              0 if success else 1, snippet))
        conn.commit()
    except Exception as e:
        logging.error(f"Error logging live command: {e}")

    return jsonify({'success': success, 'output': output})

@app.route('/api/sandbox/log_simulated/<int:scenario_id>', methods=['POST'])
def api_sandbox_log_simulated(scenario_id):
    """Log a command gõ in simulated terminal mode."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json() or {}
    command = (data.get('command') or '').strip()
    if not command:
        return jsonify({'success': False, 'message': 'Lệnh rỗng.'})
    
    conn = get_db()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        conn.execute("""
            INSERT INTO sandbox_command_log (user_id, scenario_id, command, executed_at, ip_address, exit_code, mode, output_snippet)
            VALUES (?, ?, ?, ?, ?, 0, 'simulated', NULL)
        """, (session['user_id'], scenario_id, command, now_str, request.remote_addr))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error logging simulated command: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ─── Evidence Manager (Teacher) ───────────────────────────────────────────────

@app.route('/teacher/evidence')
def teacher_evidence():
    if session.get('role') != 'teacher':
        return redirect(url_for('dashboard'))
    conn = get_db()
    scenarios = conn.execute("SELECT * FROM scenarios").fetchall()
    files = conn.execute("""
        SELECT ef.*, s.title as scenario_title
        FROM evidence_files ef
        JOIN scenarios s ON ef.scenario_id = s.id
        ORDER BY ef.scenario_id, ef.id
    """).fetchall()
    return render_template('evidence_manager.html', scenarios=scenarios, files=files,
                           docker_available=sandbox_manager.is_docker_available(),
                           image_ready=sandbox_manager.is_image_available())


@app.route('/api/teacher/rebuild_hashes', methods=['POST'])
def api_rebuild_hashes():
    """Re-scan evidence files and update hashes in DB."""
    if session.get('role') != 'teacher':
        return jsonify({'error': 'Forbidden'}), 403
    conn = get_db()
    files = conn.execute("SELECT * FROM evidence_files").fetchall()
    updated = 0
    for ev in files:
        fpath = os.path.join(EVIDENCE_BASE, ev['filepath'])
        if os.path.exists(fpath):
            h = hashlib.sha256()
            with open(fpath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            actual = h.hexdigest()
            size = os.path.getsize(fpath)
            conn.execute("UPDATE evidence_files SET sha256=?, size=? WHERE id=?",
                         (actual, size, ev['id']))
            updated += 1
    conn.commit()
    return jsonify({'success': True, 'updated': updated})


# ─── Existing routes (unchanged) ─────────────────────────────────────────────

@app.route('/submit_report/<int:scenario_id>', methods=['POST'])
def submit_report(scenario_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    report = request.form.get('report', '').strip()
    conn = get_db()
    scenario = get_scenario(conn, scenario_id)
    if not scenario:
        abort(404)
    if not user_can_access_scenario(scenario):
        abort(403)
    existing = conn.execute("SELECT * FROM progress WHERE user_id=? AND scenario_id=?",
                            (session['user_id'], scenario_id)).fetchone()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ctf_score = conn.execute("""
        SELECT SUM(ua.points_earned)
        FROM user_answers ua
        WHERE ua.user_id=? AND ua.scenario_id=? AND ua.is_correct=1
    """, (session['user_id'], scenario_id)).fetchone()[0] or 0.0
    if existing:
        t_score = existing['teacher_score'] or 0.0
        total_score = min(10.0, ctf_score + t_score)
        conn.execute("UPDATE progress SET report=?, status='submitted', score=?, submitted_at=? WHERE user_id=? AND scenario_id=?",
                     (report, total_score, now, session['user_id'], scenario_id))
    else:
        conn.execute("INSERT INTO progress (user_id,scenario_id,status,score,teacher_score,report,submitted_at) VALUES (?,?,'submitted',?,0.0,?,?)",
                     (session['user_id'], scenario_id, ctf_score, report, now))
    conn.commit()
    return redirect(url_for('dashboard'))


@app.route('/api/submit_flag/<int:scenario_id>', methods=['POST'])
def api_submit_flag(scenario_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Chưa đăng nhập'}), 401
    data = request.get_json() or {}
    question_id = data.get('question_id')
    submitted_flag = (data.get('flag') or '').strip()
    if not question_id or not submitted_flag:
        return jsonify({'success': False, 'message': 'Thiếu dữ liệu nộp flag'}), 400
    conn = get_db()
    scenario = get_scenario(conn, scenario_id)
    if not scenario:
        return jsonify({'success': False, 'message': 'Scenario không tồn tại'}), 404
    if not user_can_access_scenario(scenario):
        return jsonify({'success': False, 'message': 'Không được phép truy cập scenario này'}), 403
    question = conn.execute("SELECT * FROM questions WHERE id=? AND scenario_id=?", (question_id, scenario_id)).fetchone()
    if not question:
        return jsonify({'success': False, 'message': 'Câu hỏi không tồn tại'}), 404

    # For Scenario 3 use dynamic per-student answers instead of static DB values
    if scenario_id == 3:
        dv = get_dynamic_scenario3_values(session['user_id'])
        # Map question order to dynamic answer: Q1=PID, Q2=C2 addr, Q3=flag
        q_order = conn.execute(
            "SELECT id FROM questions WHERE scenario_id=3 ORDER BY id ASC"
        ).fetchall()
        q_ids = [r['id'] for r in q_order]
        dynamic_correct = {}
        if len(q_ids) >= 3:
            dynamic_correct[q_ids[0]] = str(dv['pid'])
            dynamic_correct[q_ids[1]] = dv['c2']
            dynamic_correct[q_ids[2]] = dv['flag']
        correct_answer = dynamic_correct.get(int(question_id), question['correct_flag'])
    else:
        correct_answer = question['correct_flag']

    is_correct = (correct_answer.strip().lower() == submitted_flag.lower())
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Determine mode & multiplier
    try:
        sb_status = sandbox_manager.get_sandbox_status(session['user_id'], scenario_id)
        if sb_status.get('mode') == 'docker_live' and sb_status.get('status') == 'running':
            actual_mode = 'docker'
        else:
            actual_mode = 'simulated'
    except Exception:
        actual_mode = 'simulated'

    multiplier = 1.0 if actual_mode == 'docker' else 0.6
    points_earned = round(question['points'] * multiplier, 2) if is_correct else 0.0

    try:
        existing = conn.execute("SELECT * FROM user_answers WHERE user_id=? AND question_id=?",
                                (session['user_id'], question_id)).fetchone()
        if existing:
            if existing['is_correct'] == 1:
                return jsonify({'success': True, 'already_solved': True, 'message': 'Đã hoàn thành câu hỏi này trước đó!'})
            conn.execute("UPDATE user_answers SET submitted_flag=?, is_correct=?, submitted_at=?, mode=?, points_earned=? WHERE user_id=? AND question_id=?",
                         (submitted_flag, 1 if is_correct else 0, now, actual_mode, points_earned, session['user_id'], question_id))
        else:
            conn.execute("INSERT INTO user_answers (user_id,scenario_id,question_id,submitted_flag,is_correct,submitted_at,mode,points_earned) VALUES (?,?,?,?,?,?,?,?)",
                         (session['user_id'], scenario_id, question_id, submitted_flag, 1 if is_correct else 0, now, actual_mode, points_earned))
        ctf_score = conn.execute("""
            SELECT SUM(ua.points_earned) FROM user_answers ua
            WHERE ua.user_id=? AND ua.scenario_id=? AND ua.is_correct=1
        """, (session['user_id'], scenario_id)).fetchone()[0] or 0.0
        progress = conn.execute("SELECT * FROM progress WHERE user_id=? AND scenario_id=?",
                                (session['user_id'], scenario_id)).fetchone()
        if progress:
            t_score = progress['teacher_score'] or 0.0
            total_score = min(10.0, ctf_score + t_score)
            new_status = progress['status'] if progress['status'] != 'not_started' else 'ongoing'
            conn.execute("UPDATE progress SET score=?, status=? WHERE user_id=? AND scenario_id=?",
                         (total_score, new_status, session['user_id'], scenario_id))
        else:
            conn.execute("INSERT INTO progress (user_id,scenario_id,status,score,teacher_score) VALUES (?,?,'ongoing',?,0.0)",
                         (session['user_id'], scenario_id, ctf_score))
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({'success': False, 'message': f'Lỗi cơ sở dữ liệu: {str(e)}'}), 500
    if is_correct:
        mode_label = "Docker Live (100% điểm)" if actual_mode == 'docker' else "Giả lập (60% điểm)"
        return jsonify({'success': True, 'message': f'Chúc mừng! Flag chính xác. +{points_earned} điểm (Chế độ: {mode_label})', 'points': points_earned})
    else:
        return jsonify({'success': False, 'message': 'Flag chưa chính xác, hãy thử lại!'})


@app.route('/grade/<int:progress_id>', methods=['POST'])
def grade(progress_id):
    if session.get('role') != 'teacher':
        return redirect(url_for('dashboard'))
    score = request.form.get('score')
    try:
        score = float(score)
        if not (0 <= score <= 4):
            raise ValueError
    except (TypeError, ValueError):
        return 'Diem bao cao khong hop le (0-4)', 400
    conn = get_db()
    prog = conn.execute("SELECT * FROM progress WHERE id=?", (progress_id,)).fetchone()
    if not prog:
        abort(404)
    ctf_score = conn.execute("""
        SELECT SUM(ua.points_earned) FROM user_answers ua
        WHERE ua.user_id=? AND ua.scenario_id=? AND ua.is_correct=1
    """, (prog['user_id'], prog['scenario_id'])).fetchone()[0] or 0.0
    total_score = min(10.0, ctf_score + score)
    conn.execute("UPDATE progress SET teacher_score=?, score=?, status='graded' WHERE id=?",
                 (score, total_score, progress_id))
    conn.commit()
    return redirect(url_for('dashboard'))


@app.route('/accounts')
def accounts():
    if session.get('role') != 'teacher':
        return redirect(url_for('dashboard'))
    conn = get_db()
    students = conn.execute("SELECT * FROM users WHERE role='student' ORDER BY id DESC").fetchall()
    return render_template('accounts.html', students=students)


@app.route('/create_account', methods=['POST'])
def create_account():
    if session.get('role') != 'teacher':
        return redirect(url_for('dashboard'))
    fullname = request.form.get('fullname', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', 'haui2026')
    if not fullname or not username:
        return redirect(url_for('accounts') + '?msg=invalid')
    pw_hash = generate_password_hash(password)
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username,password,role,fullname) VALUES (?,?,?,?)",
                     (username, pw_hash, 'student', fullname))
        conn.commit()
        msg = 'success'
    except sqlite3.IntegrityError:
        msg = 'exists'
    return redirect(url_for('accounts') + f'?msg={msg}')


@app.route('/delete_account/<int:user_id>', methods=['POST'])
def delete_account(user_id):
    if session.get('role') != 'teacher':
        return redirect(url_for('dashboard'))
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=? AND role='student'", (user_id,))
    conn.execute("DELETE FROM progress WHERE user_id=?", (user_id,))
    conn.commit()
    return redirect(url_for('accounts'))


@app.route('/reset_password/<int:user_id>', methods=['POST'])
def reset_password(user_id):
    if session.get('role') != 'teacher':
        return redirect(url_for('dashboard'))
    new_pw = request.form.get('new_password', 'haui2026')
    pw_hash = generate_password_hash(new_pw)
    conn = get_db()
    conn.execute("UPDATE users SET password=? WHERE id=?", (pw_hash, user_id))
    conn.commit()
    return redirect(url_for('accounts'))


@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', code=403, message="Ban khong co quyen truy cap trang nay."), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', code=404, message="Trang web khong ton tai."), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', code=500, message="Loi he thong noi bo."), 500


if __name__ == '__main__':
    init_db()
    sandbox_manager.start_cleanup_scheduler()
    app.run(debug=True, host='0.0.0.0', port=5000)
