from flask import Flask, request, render_template, redirect, url_for, session, jsonify, make_response, render_template_string, send_from_directory
import sqlite3
import hashlib
import base64
import os
import jwt
import datetime
import re
import html
from functools import wraps

app = Flask(__name__)
app.secret_key = 'secret_key_hogwarts_123'  


FLAG_1 = "HP_CTF{" + "th3_b0y_wh0_l1v3d"[::-1][::-1] + "}"


DATABASE = 'hogwarts.db'


class XSSFilter:
    """Advanced XSS filter that can be bypassed with creative techniques"""
    
    @staticmethod
    def basic_filter(input_str):
        """Basic blacklist filter - easy to bypass"""
        dangerous = ['<script>', '</script>', 'javascript:', 'onerror', 'onload', 'onclick']
        filtered = input_str
        for pattern in dangerous:
            filtered = filtered.replace(pattern.lower(), '')
        return filtered
    
    @staticmethod
    def advanced_filter(input_str):
        """Advanced filter - harder to bypass, but still possible"""
       
        patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe',
            r'<object',
            r'<embed',
            r'<img[^>]+onerror',
        ]
        
        filtered = input_str
        for pattern in patterns:
            filtered = re.sub(pattern, '', filtered, flags=re.IGNORECASE)
        
        return filtered
    
    @staticmethod
    def strict_filter(input_str):
        """Very strict filter - requires advanced bypass techniques"""
        
        filtered = input_str
        
        
        filtered = re.sub(r'<\s*script[^>]*>.*?<\s*/\s*script\s*>', '', filtered, flags=re.IGNORECASE | re.DOTALL)
        
  
        filtered = re.sub(r'\s*on\w+\s*=\s*["\']?[^"\']*["\']?', '', filtered, flags=re.IGNORECASE)
        
        
        filtered = re.sub(r'javascript\s*:', '', filtered, flags=re.IGNORECASE)
        
        
        filtered = re.sub(r'data\s*:', '', filtered, flags=re.IGNORECASE)
        
       
        dangerous_tags = ['iframe', 'object', 'embed', 'applet', 'meta', 'link']
        for tag in dangerous_tags:
            filtered = re.sub(f'<\s*{tag}[^>]*>', '', filtered, flags=re.IGNORECASE)
        
        return filtered

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize the database with vulnerable schema"""
    db = get_db()
    
    
    db.execute('DROP TABLE IF EXISTS users')
    db.execute('DROP TABLE IF EXISTS house_points')
    db.execute('DROP TABLE IF EXISTS spells')
    db.execute('DROP TABLE IF EXISTS secret_notes')
    db.execute('DROP TABLE IF EXISTS student_records')
    
    
    db.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            house TEXT,
            secret_info TEXT
        )
    ''')
    
    
    db.execute('''
        CREATE TABLE house_points (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            house TEXT NOT NULL,
            points INTEGER NOT NULL,
            reason TEXT,
            awarded_by TEXT
        )
    ''')
    
  
    db.execute('''
        CREATE TABLE spells (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            spell_name TEXT NOT NULL,
            incantation TEXT NOT NULL,
            effect TEXT,
            difficulty TEXT,
            secret_flag TEXT
        )
    ''')
    

    db.execute('''
        CREATE TABLE secret_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    
    db.execute('''
        CREATE TABLE student_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_name TEXT NOT NULL,
            year INTEGER,
            gpa REAL,
            private_notes TEXT,
            flag TEXT
        )
    ''')
    
   
    weak_hash = custom_encrypt("expecto")
    
    users = [
        ('harry_potter', weak_hash, 'student', 'Gryffindor', None),
        ('hermione_granger', weak_hash, 'student', 'Gryffindor', None),
        ('draco_malfoy', weak_hash, 'student', 'Slytherin', None),
        ('ron_weasley', weak_hash, 'student', 'Gryffindor', None),
        ('mcgonagall', custom_encrypt("transfiguration"), 'professor', 'Gryffindor', None),
        ('severus_snape', custom_encrypt("half_blood_prince"), 'professor', 'Slytherin', ''),
        ('albus_dumbledore', custom_encrypt("fawkes_patronus_elder"), 'headmaster', 'Gryffindor', ''),
        ('voldemort', custom_encrypt("avada_kedavra_horcrux"), 'admin', 'Slytherin', ''),
        ('dumbledore', custom_encrypt("lemon_drops"), 'admin', 'Gryffindor', None)
    ]
    
    db.executemany('INSERT INTO users (username, password, role, house, secret_info) VALUES (?, ?, ?, ?, ?)', users)
    
   
    house_points = [
        ('Gryffindor', 450, 'Bravery in Forbidden Forest', 'McGonagall'),
        ('Slytherin', 520, 'Excellence in Potions', 'Snape'),
        ('Ravenclaw', 480, 'Outstanding Research', 'Flitwick'),
        ('Hufflepuff', 430, 'Loyalty and Hard Work', 'Sprout')
    ]
    db.executemany('INSERT INTO house_points (house, points, reason, awarded_by) VALUES (?, ?, ?, ?)', house_points)
    
 
    spells = [
        ('Expelliarmus', 'ex-pel-ee-AR-mus', 'Disarming charm', 'Easy', None),
        ('Expecto Patronum', 'ex-PEK-toh pah-TROH-num', 'Conjures a Patronus', 'Advanced', None),
        ('Avada Kedavra', 'ah-VAH-dah ke-DAV-rah', 'Killing curse - Unforgivable', 'Dark Magic', None),
        ('Sectumsempra', 'sec-tum-SEM-prah', 'Slashing curse', 'Dark Magic', None),
        ('Protego Maxima', 'pro-TAY-goh MAX-ih-mah', 'Powerful shield charm', 'Advanced', None),
        ('Revelio Secretum', 'reh-VEL-ee-oh se-KREE-tum', 'Reveals hidden secrets', 'Ancient Magic', 'HP_CTF{4nc13nt_m4g1c_r3v34l3d}'),
        ('Administratum', 'ad-MIN-is-TRAH-tum', 'Ancient spell for administrative access. Hidden endpoint: /api/admin/users', 'Forbidden', None)
    ]
    db.executemany('INSERT INTO spells (spell_name, incantation, effect, difficulty, secret_flag) VALUES (?, ?, ?, ?, ?)', spells)
    
    
    notes = [
        ('Hermione', 'Remember to study for Transfiguration exam tomorrow!'),
        ('Harry', 'I saw something strange in the Room of Requirement...'),
        ('Snape', 'The Dark Lord\'s orders must be followed precisely.')
    ]
    db.executemany('INSERT INTO secret_notes (author, content) VALUES (?, ?)', notes)
    
    
    students = [
        ('Harry Potter', 6, 3.8, 'Shows promise in Defense Against Dark Arts', None),
        ('Hermione Granger', 6, 4.0, 'Exceptional student in all subjects', None),
        ('Ron Weasley', 6, 3.2, 'Good at Wizard Chess, needs improvement in studies', None),
        ('Draco Malfoy', 6, 3.5, 'Skilled in Dark Arts, attitude problems', None),
        ('Neville Longbottom', 6, 3.4, 'Excellent in Herbology', None),
        ('Luna Lovegood', 5, 3.7, 'Unique perspective on magical creatures', None),
        ('Tom Riddle', 7, 4.0, 'Extremely talented but dangerous tendencies observed. CONFIDENTIAL.', 'HP_CTF{ch4mb3r_0f_s3cr3ts_0p3n3d}')
    ]
    db.executemany('INSERT INTO student_records (student_name, year, gpa, private_notes, flag) VALUES (?, ?, ?, ?, ?)', students)
    
    db.commit()
    db.close()

def custom_encrypt(password):
    """Custom weak encryption - Caesar cipher variant with Base64"""
    
    shifted = ""
    shift = 13  
    for char in password:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            shifted += char
    
    return base64.b64encode(shifted.encode()).decode()

def custom_decrypt(encrypted):
    """Decrypt the custom encryption"""
    try:
        decoded = base64.b64decode(encrypted.encode()).decode()
        shifted = ""
        shift = 13
        for char in decoded:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                shifted += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            else:
                shifted += char
        return shifted
    except:
        return None

def create_jwt_token(username, role):
    """Create JWT token with predictable secret"""
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
   
    token = jwt.encode(payload, app.secret_key, algorithm='HS256')
    return token

def verify_jwt_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return payload
    except:
        return None


def requires_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            
            if 'user' not in session:
                return redirect(url_for('login'))
           
            if session.get('role') != role and session.get('role') != 'admin':
                return "Access Denied", 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/robots.txt')
def robots():
    """Serve robots.txt with hints to hidden endpoints"""
    return send_from_directory('.', 'robots.txt', mimetype='text/plain')

@app.route('/')
def index():
   
    response = make_response(render_template('index.html'))
  

    response.headers['try-me'] = 'c2V2ZXJ1c19zbmFwZTWxmX2Jsb29kX3ByaW5jZQ=='
    response.headers['X-Debug'] = 'aGFycnlfcG90dGVyOmV4cGVjdG8=' 
    response.headers['X-Unknown'] = 'aGVybWlvbmVfZ3JhbmdlcjpleHBlY3Rv'  
    response.headers['X-Unknown-Header1'] = 'cm9uX3dlYXNsZXk6ZXhwZWN0bw=='  
    response.headers['X-Unknown-Header2'] = 'ZHJhY29fbWFsZm95OmV4cGVjdG8='  
    response.headers['X-XSS'] = 'bWNnb25hZ2FsbDp0cmFuc2ZpZ3VyYXRpb24='  
    response.headers['X-Backup'] = 'c2V2ZXJ1c19zbmFwZTpoYWxmX2Jsb29kX3ByaW5jZQ=='  
    response.headers['X-admin']= 'bb368gs2FsbDp0cmFuc2ZpZ3VyYXRpb24'
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Removed admin credentials from here - too easy to find
        # Admin credentials are hidden elsewhere - requires deeper enumeration
        return render_template('login.html')
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABLE: SQL Injection in login
        # The query is vulnerable but requires specific bypass technique
        db = get_db()
        
        # Intentionally vulnerable query with some basic filtering
        # Users need to bypass the filter
        if "'" in username or '"' in username:
            # Filter single quotes but not other SQL injection vectors
            username = username.replace("'", "")
        
        # Still vulnerable through alternative methods
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{custom_encrypt(password)}'"
        
        try:
            cursor = db.execute(query)
            user = cursor.fetchone()
            
            if user:
                session['user'] = user['username']
                session['role'] = user['role']
                session['user_id'] = user['id']
                
                # Create JWT token and set as cookie
                token = create_jwt_token(user['username'], user['role'])
                response = make_response(redirect(url_for('dashboard')))
                response.set_cookie('auth_token', token, httponly=False)  # Intentionally not httponly
                
                return response
            else:
                return render_template('login.html', error='Invalid credentials')
        except Exception as e:
            # Leak error information - helpful for SQL injection
            return render_template('login.html', error=f'Database error: {str(e)}')
        finally:
            db.close()
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Get house points
    cursor = db.execute('SELECT * FROM house_points ORDER BY points DESC')
    house_points = cursor.fetchall()
    
    db.close()
    
    return render_template('dashboard.html', 
                         username=session['user'], 
                         role=session['role'],
                         house_points=house_points)

@app.route('/search_spells')
def search_spells():
    """Vulnerable to SQL Injection and XSS - but HEAVILY protected with WAF-like filtering"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    search_query = request.args.get('q', '')
    
    # XSS is intentionally allowed for FLAG 2 (Reflected XSS challenge)
    # No filtering applied to make this challenge accessible
    filtered_query = search_query
    
    # Check if the query contains a VALID XSS payload (for FLAG 2)
    # Must be a complete, executable payload with event handlers
    xss_detected = False
    query_lower = search_query.lower()
    
    # Check for complete XSS payloads:
    # 1. Event handlers (most common XSS)
    event_handlers = ['onerror=', 'onload=', 'onclick=', 'onmouseover=', 'onfocus=', 
                      'onblur=', 'onchange=', 'onsubmit=', 'onkeypress=', 'onmouseenter=',
                      'ontoggle=', 'onpointerover=', 'onmousemove=', 'ondblclick=']
    
    for handler in event_handlers:
        if handler in query_lower:
            xss_detected = True
            break
    
    # 2. Script tags with content (not just <script> alone)
    if not xss_detected:
        if '<script>' in query_lower and ('alert' in query_lower or 'document' in query_lower 
                                          or 'window' in query_lower or 'eval' in query_lower
                                          or 'fetch' in query_lower or 'console' in query_lower):
            xss_detected = True
    
    # 3. JavaScript protocol with function call
    if not xss_detected:
        if 'javascript:' in query_lower and ('alert' in query_lower or 'confirm' in query_lower 
                                             or 'prompt' in query_lower or 'eval' in query_lower):
            xss_detected = True
    
    # WAF-like SQL injection protection (can be bypassed with advanced techniques)
    sql_patterns = [
        'union select', 'union all select', 'union distinct',
        'or 1=1', 'or 1 =1', 'or 1= 1', 'or 1 = 1',
        'and 1=1', 'and 1 =1', 'and 1= 1', 'and 1 = 1',
        'select *', 'select.*from', 'information_schema',
        'sleep(', 'benchmark(', 'waitfor delay',
        'concat(', 'group_concat', 'load_file',
        'into outfile', 'into dumpfile',
        'exec(', 'execute(', 'sp_',
        'xp_cmdshell', 'xp_'
    ]
    
    waf_blocked = False
    for pattern in sql_patterns:
        if pattern.lower() in search_query.lower():
            waf_blocked = True
            break
    
    if waf_blocked:
        return render_template('search_spells.html', 
                             results=[], 
                             query=filtered_query,
                             xss_detected=xss_detected,
                             error="⚠️ WAF Alert: Potential SQL injection detected and blocked!")
    
    db = get_db()
    
    # SQL Injection vulnerability - Normal searches return NOTHING
    # Only SQL injection will return results
    # Restrictive WHERE clause that won't match anything normally
    # FLAG 5 is in the secret_flag column!
    query = f"SELECT spell_name, incantation, effect, difficulty, secret_flag FROM spells WHERE spell_name = '{search_query}' AND difficulty = 'Impossible' AND house = 'Forbidden'"
    
    try:
        cursor = db.execute(query)
        results = cursor.fetchall()
        db.close()
        
        # Provide feedback on query execution
        success_msg = None
        error_msg = None
        
        if results:
            success_msg = f"✓ SQL Injection successful! Found {len(results)} spell(s)."
        elif search_query:  # Query executed but no results - normal search or failed injection
            error_msg = f"⚠️ No spells found. Try a different search or use advanced techniques."
        
        return render_template('search_spells.html', 
                             results=results, 
                             query=filtered_query,
                             original_query=search_query,
                             xss_detected=xss_detected,
                             success=success_msg,
                             error=error_msg)
    except Exception as e:
        db.close()
        return render_template('search_spells.html', 
                             results=[], 
                             query=filtered_query,
                             xss_detected=xss_detected,
                             error=f"❌ Query failed")

@app.route('/student_record/<int:student_id>')
def student_record(student_id):
    """Vulnerable to IDOR - Broken Access Control"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Intentional flaw: No check if user should access this record
    # Students can access other students' private records
    
    db = get_db()
    cursor = db.execute('SELECT * FROM student_records WHERE id = ?', (student_id,))
    record = cursor.fetchone()
    db.close()
    
    if record:
        return render_template('student_record.html', record=record)
    else:
        return "Record not found", 404

@app.route('/secret_notes', methods=['GET', 'POST'])
def secret_notes():
    """Vulnerable to Stored XSS"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    if request.method == 'POST':
        content = request.form.get('content', '')
        
        # No sanitization - stored XSS vulnerability
        # But the output needs to bypass some client-side filtering
        db.execute('INSERT INTO secret_notes (author, content) VALUES (?, ?)',
                  (session['user'], content))
        db.commit()
    
    cursor = db.execute('SELECT * FROM secret_notes ORDER BY created_at DESC')
    notes = cursor.fetchall()
    db.close()
    
    return render_template('secret_notes.html', notes=notes)

@app.route('/house_points_admin', methods=['GET', 'POST'])
@requires_role('professor')
def house_points_admin():
    """Admin panel with STORED XSS vulnerability - VERY DIFFICULT with advanced filtering"""
    db = get_db()
    success_msg = None
    error_msg = None
    
    if request.method == 'POST':
        house = request.form.get('house', '')
        points = request.form.get('points', '')
        reason = request.form.get('reason', '')
        
        # Advanced XSS filter - very strict but still bypassable with expert techniques
        filtered_reason = reason
        
        # Layer 1: Remove MOST XSS vectors (but leave some bypasses possible)
        dangerous_patterns = [
            '<script', '</script>', 'javascript:', '<iframe', '<object', '<embed',
            'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur',
            '<img', '<svg', '<body', '<style', '<link', '<meta',
            'src=', 'href=', 'data:', 'vbscript:', '<form', '<input',
            '<button', '<select', '<textarea',
            '<audio', '<video'
            # Bypasses available: <details>, <marquee>, <keygen>, <math>
            # Event bypasses: ontoggle, onstart, oncut, oncopy, onpaste, ondrag, onpointerover
            # Function bypasses: eval, alert, prompt, confirm (not blocked - need creative use)
        ]
        
        for pattern in dangerous_patterns:
            if pattern.lower() in filtered_reason.lower():
                filtered_reason = filtered_reason.replace(pattern, '***')
                filtered_reason = filtered_reason.replace(pattern.upper(), '***')
                filtered_reason = filtered_reason.replace(pattern.capitalize(), '***')
        
        # Layer 2: Remove HTML entity encoding attempts
        filtered_reason = filtered_reason.replace('&#', '***')
        filtered_reason = filtered_reason.replace('&lt;', '***')
        filtered_reason = filtered_reason.replace('&gt;', '***')
        
        # Layer 3: Remove common bypass attempts
        filtered_reason = filtered_reason.replace('\\x', '***')
        filtered_reason = filtered_reason.replace('\\u', '***')
        filtered_reason = filtered_reason.replace('%3C', '***')
        filtered_reason = filtered_reason.replace('%3E', '***')
        
        # VULNERABLE: Stored XSS - filtered content is saved to database
        # The filter can still be bypassed with creative techniques!
        query = f"INSERT INTO house_points (house, points, reason, awarded_by) VALUES (?, ?, ?, ?)"
        
        try:
            db.execute(query, (house, points, filtered_reason, session['user']))
            db.commit()
            success_msg = f"✓ Successfully awarded {points} points to {house}!"
        except Exception as e:
            error_msg = f"Error: {str(e)}"
    
    # Retrieve all house points (XSS will trigger when displayed)
    cursor = db.execute('SELECT id, house, points, reason, awarded_by FROM house_points ORDER BY id DESC')
    points = cursor.fetchall()
    db.close()
    
    return render_template('house_points_admin.html', 
                         house_points=points,
                         success=success_msg,
                         error=error_msg)

@app.route('/admin_verify', methods=['GET', 'POST'])
@requires_role('admin')
def admin_verify():
    """Admin verification - requires all previous flags to be submitted"""
    error_msg = None
    success_msg = None
    
    if request.method == 'POST':
        # Define correct flags
        correct_flags = {
            'flag1': 'HP_CTF{w34k_p4ssw0rd_l3v10s4}',
            'flag2': 'HP_CTF{xss_p3trificus_t0t4lus}',
            'flag5': 'HP_CTF{sql_1nj3ct10n_s3rp3ns0rt14}',
            'flag6': 'HP_CTF{st0r3d_xss_m4lef1c4rum}',
            'flag7': 'HP_CTF{1d0r_r3v3l10_t0t4l}'
        }
        
        # Check all submitted flags
        all_correct = True
        submitted_flags = {}
        
        for flag_num in ['flag1', 'flag2', 'flag5', 'flag6', 'flag7']:
            submitted = request.form.get(flag_num, '').strip()
            submitted_flags[flag_num] = submitted
            
            if submitted != correct_flags[flag_num]:
                all_correct = False
        
        if all_correct:
            # Set verification cookie valid for 1 hour
            response = make_response(redirect(url_for('admin_panel')))
            response.set_cookie('admin_verified', 'true', max_age=3600, httponly=True)
            return response
        else:
            error_msg = "One or more flags are incorrect. You must collect all previous flags before accessing the admin panel."
    
    return render_template('admin_verify.html', error=error_msg, success=success_msg)

@app.route('/admin_panel')
@requires_role('admin')
def admin_panel():
    """Super secret admin panel - requires admin JWT only"""
    # Flag hidden here - accessible with forged admin JWT
    secret_flag = "HP_CTF{jwt_f0rg3ry_4dm1n_pwn3d}"
    
    db = get_db()
    cursor = db.execute('SELECT * FROM users')
    users = cursor.fetchall()
    db.close()
    
    return render_template('admin_panel.html', users=users, flag=secret_flag)

@app.route('/debug/cookies')
def debug_cookies():
    """Debug endpoint to check cookies"""
    auth_token = request.cookies.get('auth_token')
    all_cookies = dict(request.cookies)
    
    if auth_token:
        payload = verify_jwt_token(auth_token)
        return jsonify({
            'has_auth_token': True,
            'token_preview': auth_token[:50] + '...',
            'token_valid': payload is not None,
            'payload': payload,
            'all_cookies': all_cookies
        })
    else:
        return jsonify({
            'has_auth_token': False,
            'all_cookies': all_cookies,
            'message': 'No auth_token cookie found'
        })

@app.route('/api/user_info')
def api_user_info():
    """API endpoint that leaks information"""
    # Vulnerable: Returns sensitive info based on manipulable cookie
    auth_token = request.cookies.get('auth_token')
    
    if auth_token:
        payload = verify_jwt_token(auth_token)
        if payload:
            db = get_db()
            cursor = db.execute('SELECT username, role, house, secret_info FROM users WHERE username = ?', 
                              (payload['username'],))
            user = cursor.fetchone()
            db.close()
            
            if user:
                return jsonify({
                    'username': user['username'],
                    'role': user['role'],
                    'house': user['house'],
                    'secret_info': user['secret_info']
                })
    
    return jsonify({'error': 'Unauthorized'}), 401

@app.route('/.well-known/security.txt')
def security_info():
    """Public security contact - no credentials here"""
    response = make_response("# Security Contact Information\n# For security issues, contact: security@hogwarts.edu\n# PGP Key: Not Available\n", 200)
    response.headers['Content-Type'] = 'text/plain'
    return response

@app.route('/debug_info')
def debug_info():
    """Debug endpoint - requires admin JWT to access sensitive info"""
    auth_token = request.cookies.get('auth_token')
    
    if not auth_token:
        return jsonify({'error': 'Authentication required'}), 401
    
    payload = verify_jwt_token(auth_token)
    if not payload or payload.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    # Only accessible with forged admin JWT
    # Returns encrypted admin credentials that need to be decrypted
    return jsonify({
        'status': 'debug',
        'version': '1.0.0',
        'environment': 'development',
        'admin_backup': {
            'encrypted_creds': 'qhzoyrqber:yrzba_qebcf',  # ROT13 encoded
            'encryption_hint': 'Same cipher as user passwords',
            'note': 'Backup admin account for emergency access'
        }
    }), 200

@app.route('/api/admin/users')
def admin_users_api():
    """Hidden API endpoint - requires JWT forgery to access"""
    # This endpoint is not linked anywhere - requires enumeration
    auth_token = request.cookies.get('auth_token')
    
    if not auth_token:
        return jsonify({'error': 'Authentication required'}), 401
    
    payload = verify_jwt_token(auth_token)
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    
    # Only returns admin info if role is admin or headmaster
    if payload.get('role') not in ['admin', 'headmaster']:
        return jsonify({'error': 'Insufficient privileges', 'hint': 'Admin or Headmaster role required'}), 403
    
    # Returns list of admin usernames (but not passwords)
    # User must then use other techniques to get passwords
    db = get_db()
    cursor = db.execute("SELECT username, role FROM users WHERE role IN ('admin', 'headmaster')")
    admin_users = cursor.fetchall()
    db.close()
    
    return jsonify({
        'message': 'Admin users retrieved successfully',
        'users': [{'username': u['username'], 'role': u['role']} for u in admin_users],
        'note': 'Passwords are encrypted in database. Check debug_info endpoint for backup credentials.'
    }), 200

@app.route('/cipher_challenge')
def cipher_challenge():
    """A cryptography challenge page"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Encrypted message using custom cipher
    encrypted_msg = "VGhlIGZpbmFsIGZsYWcgaXMgaGlkZGVuIGluIHRoZSBDaGFtYmVyIG9mIFNlY3JldHMuIFVzZSB0aGUgcGFzc3dvcmQ6IGZfcDNyZWJhbG9pZGhlX3RfcjFfMm8uIHRoZSBrZXkgd29yZCBpIHNlY3JldF9mbGFnLiBUYWJsZTogc3BlbGxz"
    
    return render_template('cipher_challenge.html', encrypted_msg=encrypted_msg)

# FLAGS 3 & 4 REMOVED per user request
# @app.route('/dom_xss_page')
# def dom_xss_page():
#     """Page vulnerable to DOM-based XSS"""
#     if 'user' not in session:
#         return redirect(url_for('login'))
#     
#     return render_template('dom_xss.html')

@app.route('/logout')
def logout():
    session.clear()
    response = make_response(redirect(url_for('index')))
    response.set_cookie('auth_token', '', expires=0)
    return response

# Old debug_info route removed - now using the new admin JWT-protected version above

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """User profile with multiple XSS contexts - VERY HARD"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        quote = request.form.get('quote', '')
        website = request.form.get('website', '')
        
        # Apply strict filter (but can still be bypassed)
        filtered_bio = XSSFilter.strict_filter(bio)
        filtered_quote = XSSFilter.advanced_filter(quote)
        # Website is barely filtered (attribute context XSS)
        filtered_website = website.replace('"', '&quot;').replace("'", '&#39;')
        
        # Update user profile
        db.execute('''UPDATE users SET secret_info = ? WHERE username = ?''',
                  (f'bio:{filtered_bio}|quote:{filtered_quote}|website:{filtered_website}', session['user']))
        db.commit()
    
    cursor = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],))
    user = cursor.fetchone()
    db.close()
    
    # Parse profile data
    profile_data = {'bio': '', 'quote': '', 'website': ''}
    if user and user['secret_info'] and user['secret_info'].startswith('bio:'):
        parts = user['secret_info'].split('|')
        for part in parts:
            if ':' in part:
                key, value = part.split(':', 1)
                profile_data[key] = value
    
    return render_template('profile.html', user=user, profile=profile_data)

@app.route('/comments', methods=['GET', 'POST'])
def comments():
    """Comment system with mutation XSS (mXSS) - EXTREMELY HARD"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Create comments table if it doesn't exist
    try:
        db.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        db.commit()
    except:
        pass
    
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        
        # Strict HTML sanitization - but vulnerable to mXSS
        # The filter removes dangerous patterns, but browser parsing can resurrect them
        sanitized = XSSFilter.strict_filter(comment)
        
        # Additional "safe" processing that actually enables mXSS
        # Browsers may parse nested structures differently
        sanitized = html.unescape(sanitized)  # This can enable mXSS!
        
        db.execute('INSERT INTO comments (username, comment) VALUES (?, ?)',
                  (session['user'], sanitized))
        db.commit()
    
    cursor = db.execute('SELECT * FROM comments ORDER BY created_at DESC LIMIT 50')
    comments = cursor.fetchall()
    db.close()
    
    return render_template('comments.html', comments=comments)

@app.route('/search_advanced')
def search_advanced():
    """Advanced search with CSP and strict filters - MASTER LEVEL"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    query = request.args.get('q', '')
    search_type = request.args.get('type', 'all')
    
    # Triple-layer filtering
    filtered = XSSFilter.strict_filter(query)
    filtered = html.escape(filtered, quote=True)
    
    # But... there's a bypass in the template rendering
    # The filter is too aggressive and removes legitimate content
    # Users might try to "fix" it by double-encoding
    
    results = []
    flag_found = False
    
    if query:
        # Hidden flag for advanced XSS bypass
        if '<xss' in query.lower() and 'bypass' in query.lower():
            flag_found = True
    
    response = make_response(render_template('search_advanced.html', 
                                            query=filtered, 
                                            original_query=query,
                                            search_type=search_type,
                                            results=results,
                                            flag_found=flag_found))
    
    # Weak CSP that can be bypassed
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
    
    return response

@app.route('/wizard_chat', methods=['GET', 'POST'])
def wizard_chat():
    """Chat system with template injection - EXTREMELY HARD"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    message = ''
    response_text = ''
    
    if request.method == 'POST':
        message = request.form.get('message', '')
        
        # SSTI vulnerability - very hard to find and exploit
        # The message is passed to render_template_string
        # But with heavy filtering that needs to be bypassed
        
        # Remove obvious SSTI patterns
        dangerous_patterns = [
            '{{', '}}', '{%', '%}', 'config', '__class__', '__mro__', 
            'subprocess', 'os.', 'eval', 'exec', 'import'
        ]
        
        filtered_message = message
        for pattern in dangerous_patterns:
            filtered_message = filtered_message.replace(pattern, '')
        
        # Template rendering (SSTI if filter bypassed)
        template = f'''
        <div class="message">
            <strong>You:</strong> {filtered_message}
        </div>
        <div class="response">
            <strong>Sorting Hat:</strong> I sense great power in your words...
        </div>
        '''
        
        try:
            # Vulnerable to SSTI if filters are bypassed
            response_text = render_template_string(template)
        except Exception as e:
            response_text = '<div class="error">The Sorting Hat is confused...</div>'
    
    return render_template('wizard_chat.html', message=message, response=response_text)

@app.route('/spell_book')
def spell_book():
    """Spell book with reflected XSS in multiple contexts - HARD"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    spell_name = request.args.get('spell', '')
    category = request.args.get('category', 'all')
    sort_by = request.args.get('sort', 'name')
    
    # Different filtering for different parameters
    # spell_name: strict filter
    filtered_spell = XSSFilter.strict_filter(spell_name)
    
    # category: basic filter (easier to bypass)
    filtered_category = XSSFilter.basic_filter(category)
    
    # sort_by: no filter (JavaScript context XSS)
    # This goes into a JavaScript variable - different exploitation context
    
    db = get_db()
    cursor = db.execute('SELECT * FROM spells')
    spells = cursor.fetchall()
    db.close()
    
    return render_template('spell_book.html', 
                         spell_name=filtered_spell,
                         category=filtered_category,
                         sort_by=sort_by,  # No filter - JS context
                         spells=spells)

@app.route('/potion_maker', methods=['GET', 'POST'])
def potion_maker():
    """Potion maker with DOM Clobbering and advanced XSS - VERY HARD"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    ingredients = []
    potion_name = ''
    
    if request.method == 'POST':
        potion_name = request.form.get('potion_name', '')
        ingredient_list = request.form.get('ingredients', '')
        
        # Parse ingredients
        ingredients = [ing.strip() for ing in ingredient_list.split(',') if ing.strip()]
        
        # Filter potion name with advanced filter
        filtered_name = XSSFilter.advanced_filter(potion_name)
        
        # But ingredients are stored with minimal filtering (DOM clobbering possible)
        # ID attributes can be used for DOM clobbering
    
    return render_template('potion_maker.html', 
                         potion_name=potion_name,
                         ingredients=ingredients)

@app.route('/redirect')
def redirect_page():
    """Open redirect with XSS potential - MEDIUM"""
    url = request.args.get('url', '/')
    
    # Basic validation (can be bypassed)
    if url.startswith('http://') or url.startswith('https://'):
        # External redirect blocked... or is it?
        if 'localhost' not in url and '127.0.0.1' not in url:
            return "External redirects are not allowed", 403
    
    # JavaScript redirect with XSS potential
    return render_template('redirect.html', url=url)

@app.route('/gradeboard')
def gradeboard():
    """Gradeboard with SQL injection AND XSS - EXPERT LEVEL"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    student_name = request.args.get('student', '')
    subject = request.args.get('subject', '')
    
    # SQL injection with WAF-like protection
    # Multiple filters that need to be chained to bypass
    sql_filters = ['union', 'select', 'drop', 'insert', 'update', 'delete', '--', ';', '/*', '*/', 'or 1=1']
    
    filtered_name = student_name
    for f in sql_filters:
        # Case-insensitive removal
        filtered_name = re.sub(f, '', filtered_name, flags=re.IGNORECASE)
    
    # But the filter can be bypassed with double encoding or alternative syntax
    
    db = get_db()
    try:
        # Still vulnerable if filter is bypassed
        query = f"SELECT * FROM student_records WHERE student_name LIKE '%{filtered_name}%'"
        cursor = db.execute(query)
        results = cursor.fetchall()
    except Exception as e:
        results = []
        filtered_name = f"Error: {str(e)}"
    
    db.close()
    
    # XSS in the output (both name and subject)
    # subject has basic filter, name has strict filter
    filtered_subject = XSSFilter.basic_filter(subject)
    
    return render_template('gradeboard.html', 
                         student_name=filtered_name,
                         subject=filtered_subject,
                         results=results)

@app.route('/set_admin_jwt')
def set_admin_jwt():
    """Helper endpoint to set admin JWT token via server-side cookie"""
    # Pre-generated admin JWT token
    admin_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImhhcnJ5X3BvdHRlciIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc2MjA3MTI3OX0.g6apPAAPspoyv6JQGKcJHr97kJEsCh9bs3_tvXXoHH4"
    
    # CRITICAL: Also set the session with admin role
    session['user'] = 'harry_potter'
    session['role'] = 'admin'
    session['house'] = 'Gryffindor'
    
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin JWT Set</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                color: white;
                text-align: center;
            }
            .container {
                background: rgba(255, 255, 255, 0.1);
                padding: 50px;
                border-radius: 15px;
                backdrop-filter: blur(10px);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            }
            h1 { color: #4ade80; margin-bottom: 20px; }
            .success { font-size: 64px; margin-bottom: 20px; }
            a {
                display: inline-block;
                background: #4ade80;
                color: white;
                text-decoration: none;
                padding: 15px 30px;
                border-radius: 8px;
                margin: 10px;
                font-weight: bold;
            }
            a:hover { background: #22c55e; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success">✓</div>
            <h1>Admin JWT Token Set Successfully!</h1>
            <p>You now have admin privileges</p>
            <p>Role: <strong>admin</strong></p>
            <p>Username: <strong>harry_potter</strong></p>
            <br>
            <a href="/debug/cookies">Check Cookie Status</a>
            <a href="/admin_verify">Go to Admin Verify</a>
            <a href="/dashboard">Go to Dashboard</a>
        </div>
    </body>
    </html>
    """)
    
    # Set the admin JWT token as a cookie
    response.set_cookie('auth_token', admin_token, max_age=86400, httponly=True, path='/')
    
    return response

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True, host='0.0.0.0', port=8080)

