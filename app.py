import base64
import os
import sqlite3
from flask import Flask, flash, jsonify, redirect, render_template, request, session

app = Flask(__name__)
app.secret_key = 'kominfo_secret_key'

# RUMUS AFFINE CIPHER
A = 15
B = 10
M = 256
A_INV = 239


def init_db():
  """Membuat tabel dan akun admin otomatis jika belum ada di Railway."""
  try:
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT NOT NULL,
                username TEXT NOT NULL,
                password_encrypted TEXT NOT NULL
            )
        """)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
      cursor.execute(
          "INSERT INTO users (username, password, role) VALUES ('admin',"
          " 'admin123', 'admin')"
      )
    conn.commit()
    conn.close()
  except Exception as e:
    print(f'DB Error: {e}')


def encrypt_affine(text):
  encrypted_bytes = bytearray()
  for char in text:
    x = ord(char) % M
    enc_val = (A * x + B) % M
    encrypted_bytes.append(enc_val)
  return base64.b64encode(encrypted_bytes).decode('utf-8')


def decrypt_affine(text):
  try:
    encrypted_bytes = base64.b64decode(text.encode('utf-8'))
    decrypted = ''
    for byte in encrypted_bytes:
      y = byte
      dec_val = (A_INV * (y - B)) % M
      decrypted += chr(dec_val)
    return decrypted
  except Exception:
    return text


# 1. ROUTE UTAMA
@app.route('/')
def home():
  init_db()  # Pastikan DB dibuat saat pertama kali web dibuka
  if 'username' in session:
    return redirect('/dashboard')
  return redirect('/login')


# 2. ROUTE LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
  init_db()
  if request.method == 'POST':
    username = request.form.get('username')
    password = request.form.get('password')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, username, password, role FROM users WHERE username = ? AND'
        ' password = ?',
        (username, password),
    )
    user = cursor.fetchone()
    conn.close()

    if user:
      session['username'] = user[1]
      session['role'] = user[3]
      return redirect('/dashboard')
    else:
      flash('Username atau password salah!', 'danger')

  return render_template('login.html')


# 3. ROUTE LOGOUT
@app.route('/logout')
def logout():
  session.clear()
  return redirect('/login')


# 4. ROUTE DASHBOARD
@app.route('/dashboard')
def dashboard():
  if 'username' not in session:
    return redirect('/login')

  init_db()
  conn = sqlite3.connect('database.db')
  cursor = conn.cursor()
  cursor.execute(
      'SELECT id, service_name, username, password_encrypted FROM credentials'
  )
  credentials = cursor.fetchall()
  cursor.execute('SELECT id, username, role FROM users')
  users = cursor.fetchall()
  conn.close()

  return render_template(
      'dashboard.html', credentials=credentials, users=users
  )


# 5. ROUTE TAMBAH KREDENSIAL
@app.route('/add_credential', methods=['POST'])
def add_credential():
  if 'username' not in session or session.get('role', '').lower() != 'admin':
    return redirect('/dashboard')

  service_name = request.form.get('service_name', '')
  username = request.form.get('username', '')
  password_plain = request.form.get('password', '')
  password_encrypted = encrypt_affine(password_plain)

  conn = sqlite3.connect('database.db')
  cursor = conn.cursor()
  cursor.execute(
      'INSERT INTO credentials (service_name, username, password_encrypted)'
      ' VALUES (?, ?, ?)',
      (service_name, username, password_encrypted),
  )
  conn.commit()
  conn.close()

  flash('Kredensial baru berhasil disimpan!', 'success')
  return redirect('/dashboard')


# 6. ROUTE TAMBAH USER
@app.route('/add_user', methods=['POST'])
def add_user():
  if 'username' not in session or session.get('role', '').lower() != 'admin':
    return redirect('/dashboard')

  username = request.form.get('username', '')
  password = request.form.get('password', '')
  role = request.form.get('role', 'staf')

  conn = sqlite3.connect('database.db')
  cursor = conn.cursor()
  try:
    cursor.execute(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        (username, password, role),
    )
    conn.commit()
    flash('User baru berhasil ditambahkan!', 'success')
  except sqlite3.IntegrityError:
    flash('Username sudah terdaftar!', 'danger')
  finally:
    conn.close()

  return redirect('/dashboard')


# 7. ROUTE GET PASSWORD (DECRYPT)
@app.route('/get_password/<int:id>')
def get_password(id):
  conn = sqlite3.connect('database.db')
  cursor = conn.cursor()
  cursor.execute(
      'SELECT password_encrypted FROM credentials WHERE id = ?', (id,)
  )
  row = cursor.fetchone()
  conn.close()

  if row:
    decrypted_password = decrypt_affine(row[0])
    return jsonify({'password': decrypted_password})
  return jsonify({'password': 'Gagal mengambil password'}), 404


# 8. ROUTE HAPUS KREDENSIAL
@app.route('/delete_credential/<int:id>')
def delete_credential(id):
  if 'username' not in session or session.get('role', '').lower() != 'admin':
    return redirect('/dashboard')

  conn = sqlite3.connect('database.db')
  cursor = conn.cursor()
  cursor.execute('DELETE FROM credentials WHERE id = ?', (id,))
  conn.commit()
  conn.close()

  flash('Kredensial berhasil dihapus!', 'warning')
  return redirect('/dashboard')


# 9. ROUTE HAPUS USER
@app.route('/delete_user/<int:id>')
def delete_user(id):
  if 'username' not in session or session.get('role', '').lower() != 'admin':
    return redirect('/dashboard')

  conn = sqlite3.connect('database.db')
  cursor = conn.cursor()
  cursor.execute('DELETE FROM users WHERE id = ?', (id,))
  conn.commit()
  conn.close()

  flash('User berhasil dihapus!', 'warning')
  return redirect('/dashboard')


if __name__ == '__main__':
  port = int(os.environ.get('PORT', 5000))
  app.run(host='0.0.0.0', port=port)