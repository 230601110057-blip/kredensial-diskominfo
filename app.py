from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import sqlite3
import math

app = Flask(__name__)
app.secret_key = 'kunci_rahasia_diskominfo_batu'

# --- 1. METODE MATEMATIKA: AFFINE CIPHER ---
a = 5
b = 8
m = 256  # Menggunakan jangkauan ASCII (0-255)

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

a_inv = mod_inverse(a, m)

def encrypt_affine(text):
    cipher = ""
    for char in text:
        x = ord(char)
        enc_char = (a * x + b) % m
        cipher += chr(enc_char)
    return cipher

def decrypt_affine(cipher):
    plain = ""
    for char in cipher:
        y = ord(char)
        dec_char = (a_inv * (y - b)) % m
        plain += chr(dec_char)
    return plain

# --- 2. INISIALISASI DATABASE SQLITE ---
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Tabel Users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            status INTEGER DEFAULT 1
        )
    ''')
    
    # Tabel Kredensial
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama_sistem TEXT,
            username_sistem TEXT,
            password_encrypted TEXT
        )
    ''')
    
    # Buat Akun Admin Default & Data Dummy jika belum ada
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, role, status) VALUES ('admin', 'admin123', 'Admin', 1)")
        cursor.execute("INSERT INTO users (username, password, role, status) VALUES ('pkl_stat', 'pkl123', 'Staf/PKL', 1)")
        
        # Masukkan sampel akun ROMANTIK (Password di-enkripsi dengan Affine Cipher)
        pass_encrypted = encrypt_affine("takoksengero")
        cursor.execute("INSERT INTO credentials (nama_sistem, username_sistem, password_encrypted) VALUES (?, ?, ?)",
                       ('ROMANTIK BPS', 'dastatkominfo@batukota.go.id', pass_encrypted))
        
    conn.commit()
    conn.close()

init_db()

# --- 3. ROUTING APLIKASI WEB ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ? AND status = 1", (user, pwd))
        account = cursor.fetchone()
        conn.close()
        
        if account:
            session['loggedin'] = True
            session['username'] = account[1]
            session['role'] = account[3]
            return redirect(url_for('dashboard'))
        else:
            return "Login Gagal! Username/Password salah atau akun nonaktif."
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('loggedin'):
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM credentials")
    data_kredensial = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', data=data_kredensial, user=session['username'], role=session['role'])

# ROUTE UNTUK TAMBAH USER BARU (Dipindahkan ke posisi yang benar)
@app.route('/tambah_user', methods=['POST'])
def tambah_user():
    if not session.get('loggedin'):
        return redirect(url_for('login'))

    username_baru = request.form.get('username')
    password_baru = request.form.get('password')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        # Menambahkan user baru dengan default role 'Staf/PKL' dan status 1 (Aktif)
        cursor.execute("INSERT INTO users (username, password, role, status) VALUES (?, ?, 'Staf/PKL', 1)", 
                       (username_baru, password_baru))
        conn.commit()
        flash("User baru berhasil ditambahkan!")
    except sqlite3.IntegrityError:
        flash("Username sudah ada!")
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

# API untuk pemicu Dekripsi Matematika saat ikon mata diklik
@app.route('/decrypt/<int:id>', methods=['POST'])
def get_decrypted_password(id):
    if not session.get('loggedin'):
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_encrypted FROM credentials WHERE id = ?", (id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        password_asli = decrypt_affine(row[0])
        return jsonify({'password': password_asli})
    return jsonify({'error': 'Data not found'}), 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)