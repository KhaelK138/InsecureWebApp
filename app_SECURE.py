from flask import Flask, request, render_template, redirect, session
import sqlite3
import subprocess
from flask_bcrypt import Bcrypt 
from validate_email import validate_email
import re

app = Flask(__name__)

# hashing passwords
bcrypt = Bcrypt(app) 

# Fixed: stored secret key in config file. 
configfile = open('./config/config.config', 'r')

# Fixed: use flask's signed session tokens with a secret key
app.secret_key = configfile.readline().strip()

# Path to SQLite database
DATABASE = 'database_secure.db'

# Admin stuff
admin_username = configfile.readline().strip()
admin_email = configfile.readline().strip()
admin_password = configfile.readline().strip()

# Initialize database schema
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema_secure.sql', mode='r') as f:
            db.cursor().executescript(f.read())

        cursor = db.cursor()
        # Fixed: admin creds from config file, rather than plaintext; password is better
        
        cursor.execute("SELECT COUNT(*) FROM users")
        if not cursor.fetchone()[0]:
            cursor.execute("INSERT INTO users (username, email, password, balance, admin) VALUES (?, ?, ?, ?, ?)", (admin_username, admin_email, bcrypt.generate_password_hash(admin_password).decode('utf-8'), 1338, 1))
            # Not really vulnerable; these users are just static examples and would normally be created through the app
            cursor.execute("INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)", ("johndoe", "jdoe@gmail.com", bcrypt.generate_password_hash("Password123!").decode('utf-8'), 100))
            cursor.execute("INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)", ("haxor", "haxor@gmail.com", bcrypt.generate_password_hash("Pr0v4b1yS3cur3!").decode('utf-8'), 100))

        # Statically create example comments
        comment_username_1 = "johndoe"
        comment_content_1 = "All my money is still here. Chilling 👍🏼 10/10"
        comment_username_2 = "haxor"
        comment_content_2 = "No more bold comments :("
        cursor.execute("SELECT COUNT(*) FROM comments")
        if not cursor.fetchone()[0]:
            cursor.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (comment_username_1, comment_content_1))
            cursor.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (comment_username_2, comment_content_2))
        
        db.commit()


# Connect to the SQLite database
def get_db():
    db = sqlite3.connect(DATABASE)
    return db
 

@app.route('/')
def serve_file():
    # Fixed: no more serving arbitrary files from URL parameters
    # /stocks is now its own page
    
    return render_template('index_secure.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
       
        conn = get_db()
        cursor = conn.cursor()
        # Fixed: no more SQL injection
        try:
            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
            user = cursor.fetchone()
            if user:

                is_valid = bcrypt.check_password_hash(user[3], password) 
                if is_valid:
                    session['username'] = user[1]
                    return redirect('/dashboard')
                error = 'Invalid email or password'
            else:
                error = 'Invalid email or password'
        except sqlite3.Error as e:
            error = f"{str(e)}"
    return render_template('login_secure.html', error=error)


# Dashboard page
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/')

    username = session['username']
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT balance FROM users WHERE username=?", (username,))
    balance = cursor.fetchone()[0]

    # Fixed: usernames are no longer used for sign-in, so displaying them is ok!
    cursor.execute("SELECT username, content FROM comments")
    comments = cursor.fetchall()
    # Fixed: check if the user is an admin
    cursor.execute("SELECT admin FROM users WHERE username=?", (username,))
    admin = True if cursor.fetchone()[0] else False

    return render_template('dashboard_secure.html', username=username, balance=balance, is_admin=admin, comments=comments)

# Add a comment
@app.route('/add_comment', methods=['POST'])
def add_comment():
    if 'username' not in session:
        return redirect('/')
    
    username = session['username'] 
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
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8') 

        
        valid_email = validate_email(email)
        valid_email2 = check(email)

        if not valid_email or not valid_email2:
            return render_template('error.html', error="Enter a valid email")

        balance = 100
        conn = get_db()
        cursor = conn.cursor()
        if password == "" or username == "":
            return render_template('register_secure.html', error='All fields must not be empty')
        try:
            cursor.execute("INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)", (username, email, hashed_password, balance))
            conn.commit()
            # Fixed: uses flask's secure sessions with a secret key
            session['username'] = username
            return redirect('/dashboard')
        except sqlite3.IntegrityError:
            # Fixed: enumerating for emails is much more difficult
            # TODO add captcha to prevent brute forces
            return render_template('register_secure.html', error='Email or Username already exists')
    return render_template('register_secure.html')

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'username' not in session:
        return redirect('/')

    username = session['username']
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Delete the user account based on the provided username
        cursor.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()

        # Clear the session to log the user out
        session.clear()

        return redirect('/')
    except Exception as e:
        # Handle any errors that occur during the deletion process
        render_template('register.html', error="User not found")

@app.route('/insert', methods=['GET', 'POST'])
def insert():
    # Fixed: No more unpickling user data on hidden endpoint. 
    return render_template('error.html', error='Unpickling user databases is no longer supported (and for good reason).')


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
        # Fixed: server side checking for negative amounts or transferring to self
        if amount <= 0 or recipient == session['username']:
            return render_template('transfer_secure.html', error='What are you tryna do 🤔🤨')
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
                # Fixed: Usernames are no longer needed for sign in, so they're ok to enumerate
                return render_template('transfer_secure.html', error='Receiver Account Not Found')
        else:
            return render_template('transfer_secure.html', error='You are too broke for that (womp womp)')
    return render_template('transfer_secure.html')

# Fixed: Stocks has its own page
@app.route('/stocks')
def stocks():
    return render_template('stocks.html', stocks=stocks)

# Admin page
@app.route('/admin')
def admin():
    # Fixed: administrative privileges from database
    username = session['username']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT admin FROM users WHERE username=?", (username,))
    admin = True if cursor.fetchone()[0] else False
    if admin:
        # Fixed: only username, email, and balances are shown to admins
        cursor.execute("SELECT username,email,balance FROM users")
        users = cursor.fetchall()
        return render_template('admin_secure.html', users=users)
    else:
        return render_template('error.html', error="You are not an admin (I think)")


# Admin update balance
@app.route('/admin/update_balance', methods=['POST'])
def update_balance():
    username = session['username']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT admin FROM users WHERE username=?", (username,))
    admin = True if cursor.fetchone()[0] else False
    if admin:
        username = request.form['username']
        new_balance = request.form['balance']
        try:
            cursor.execute("UPDATE users SET balance=? WHERE username=?", (new_balance, username))
            conn.commit()
            return redirect('/admin')
        except:
            return render_template('error.html', error="Please enter legitimate values")
    else:
        return redirect('/')

 
# Validate email with Regex function--GeeksForGeeks
def check(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    return re.fullmatch(regex, email)

@app.route('/subscribe', methods=['POST'])
def subscribe():
   
    email = request.form.get('email')

    # Fixed: validate/sanitize emails
    valid_email = validate_email(email)
    valid_email2 = check(email)

    if valid_email and valid_email2:
        command = f"echo Subscribed {email}."
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            error = f"Success: {result.stdout.strip()}"
        else:
            error = f"Error: {result.stderr.strip()}"

        return render_template('index.html', error=error)
    return render_template('error.html', error="Enter a valid email")

# Logout route
@app.route('/logout')
def logout():
    # STILL VULNERABLE: flask sessions cannot be easily invalidated, so old sessions can still be used
    # TODO salt sessions?
    session.pop('username', None)
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=1338)

