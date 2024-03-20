from flask import Flask, request, render_template, redirect, session
import sqlite3
import os
import subprocess

app = Flask(__name__)
# Vulnerable: Plaintext Secrets
app.secret_key = 'super_secret_key_for_database'

# Path to SQLite database
DATABASE = 'database.db'

# Initialize database schema
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())

        # Vulnerable: plaintext secrets and bad password
        cursor = db.cursor()
        admin_username = "admin"
        admin_password = "admin" 
        cursor.execute("SELECT COUNT(*) FROM users WHERE username=?", ("admin",))
        if not cursor.fetchone()[0]:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (admin_username, admin_password))

        # Create example stocks
        stock_name_1 = "Secure Banking | Rating: A+"
        stock_price_1 = 30.00
        stock_name_2 = "ISSS Stock | Rating: A-"
        stock_price_2 = 20.00
        stock_name_3 = "Cantaloupe Stock | Rating: F"
        stock_price_3 = 00.01
        cursor.execute("SELECT COUNT(*) FROM stocks")
        if not cursor.fetchone()[0]:
            cursor.execute("INSERT INTO stocks (name, price) VALUES (?, ?)", (stock_name_1, stock_price_1))
            cursor.execute("INSERT INTO stocks (name, price) VALUES (?, ?)", (stock_name_2, stock_price_2))
            cursor.execute("INSERT INTO stocks (name, price) VALUES (?, ?)", (stock_name_3, stock_price_3))

        # Create comments
        comment_username_1 = "johndoe"
        comment_content_1 = "All my money disappeared. 0/10"
        comment_username_2 = "haxor"
        comment_content_2 = "<b>This text is bold... interesting...</b>"
        cursor.execute("SELECT COUNT(*) FROM comments")
        if not cursor.fetchone()[0]:
            cursor.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (comment_username_1, comment_content_1))
            cursor.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (comment_username_2, comment_content_2))
        
        db.commit()


# Connect to the SQLite database
def get_db():
    db = sqlite3.connect(DATABASE)
    return db

# Home page with login form
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        cursor = conn.cursor()
        # Vulnerable: Directly concatenating user input into the SQL query
        query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                # Vulnerable: Using only the username as a session token
                session['username'] = user[1]
                return redirect('/dashboard')
            else:
                error = 'Invalid username or password'
        except sqlite3.Error as e:
            error = f"{str(e)}"
    return render_template('login.html', error=error)


# Dashboard page
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/')

    username = session['username']
    conn = get_db()
    cursor = conn.cursor()

    # Fetch user balance
    cursor.execute("SELECT balance FROM users WHERE username=?", (username,))
    balance = cursor.fetchone()[0]

    # Fetch comments
    cursor.execute("SELECT username, content FROM comments")
    comments = cursor.fetchall()
    # Check if the user is an admin
    is_admin = True if username == 'admin' else False

    return render_template('dashboard.html', username=username, balance=balance, is_admin=is_admin, comments=comments)

# Add a comment
@app.route('/add_comment', methods=['POST'])
def add_comment():
    if 'username' not in session:
        return redirect('/')
    
    username = session['username']  # Assuming you store the user's ID in the session
    content = request.form['content']

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (username, content))
    conn.commit()

    return redirect('/dashboard')

# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        cursor = conn.cursor()
        if password == "" or username == "":
            return render_template('register.html', error='Both fields must not be empty')
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            session['username'] = username
            return redirect('/dashboard')
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists')
    return render_template('register.html')

# Transfer money page
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'username' not in session:
        return redirect('/')
    if request.method == 'POST':
        recipient = request.form['recipient']
        try: 
            amount = float(request.form['amount'])
        except:
            return render_template('transfer.html', error='Enter a number')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT balance FROM users WHERE username=?", (session['username'],))
        sender_balance = cursor.fetchone()[0]
        if sender_balance >= amount:
            cursor.execute("SELECT balance FROM users WHERE username=?", (recipient,))

            recipient_data = cursor.fetchone()
            if recipient_data:
                recipient_balance = recipient_data[0]
                
                # Update recipient's balance
                cursor.execute("UPDATE users SET balance=? WHERE username=?", (recipient_balance + amount, recipient))

                # Update sender's balance
                cursor.execute("UPDATE users SET balance=? WHERE username=?", (sender_balance - amount, session['username']))

                conn.commit()
                return redirect('/dashboard')
            else:
                # Redirect or display an error message indicating that the recipient doesn't exist
                return render_template('transfer.html', error='Receiver Account Not Found')
        else:
            return render_template('transfer.html', error='Insufficient funds')
    return render_template('transfer.html')

# Stocks page
@app.route('/stocks')
def stocks():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name, price FROM stocks")
    stocks = cursor.fetchall()
    return render_template('stocks.html', stocks=stocks)



# Admin page
@app.route('/admin')
def admin():
    # cleartext secret
    if 'username' in session and session['username'] == 'admin':
        conn = get_db()
        cursor = conn.cursor()
        # Vulnerable: admins should not be able to see all user's passwords
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        return render_template('admin.html', users=users)
    else:
        return render_template('error.html', error="You are not an admin (I think)")


# Admin update balance
@app.route('/admin/update_balance', methods=['POST'])
def update_balance():
    if 'username' in session and session['username'] == 'admin':
        username = request.form['username']
        new_balance = request.form['balance']
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET balance=? WHERE username=?", (new_balance, username))
            conn.commit()
            return redirect('/admin')
        except sqlite3.Error as e:
            error = f"An error occurred: {str(e)}"
            return render_template('error.html', error=error)
    else:
        return redirect('/')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')

    # Command injection vulnerability - this is meant to simulate using the command line to add an email
    command = f"echo Subscribed {email}."
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        error = f"Success: {result.stdout.strip()}"
    else:
        error = f"Error: {result.stderr.strip()}"

    return render_template('index.html', error=error)



# Logout route
@app.route('/logout')
def logout():
    # Vulnerable: we need to invalidate the user's old session
    session.pop('username', None)
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=1338)

