from flask import Flask, request, render_template, redirect, send_file, make_response
from datetime import timedelta
import sqlite3
import subprocess
import base64
import pickle
import argparse
import os

app = Flask(__name__)

# Vulnerable: Plaintext Secrets
app.secret_key = 'super_secret_auth_key'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = timedelta(days=1)

# Path to SQLite database
DATABASE = 'database.db'

# Initialize database schema
def init_db():
    os.remove("database.db")
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())

        cursor = db.cursor()
        # Vulnerable: plaintext secrets; bad Administrator password
        admin_username = "admin"
        admin_password = "123456" 
        cursor.execute("SELECT COUNT(*) FROM users")
        if not cursor.fetchone()[0]:
            cursor.execute("INSERT INTO users (username, password, balance) VALUES (?, ?, ?)", (admin_username, admin_password, 1338))
            # Not really vulnerable; these users are just examples and would normally be created through the app
            cursor.execute("INSERT INTO users (username, password, balance) VALUES (?, ?, ?)", ("johndoe", "Password123!", -9899))
            cursor.execute("INSERT INTO users (username, password, balance) VALUES (?, ?, ?)", ("haxor", "Pr0v4b1yIns3cur3!", 9999))

        # Create comments
        comment_username_1 = "johndoe"
        comment_content_1 = "All my money disappeared. I'm literally in debt. 0/10"
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

def validate_user(b64_username):
    if not b64_username:
        return False

    try:
        username = base64.b64decode(b64_username.encode('utf-8')).decode('utf-8')
    except:
        return False

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    return username if cursor.fetchone() else False
    

# Dashboard page
@app.route('/dashboard')
def dashboard():
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')
    
    conn = get_db()
    cursor = conn.cursor()

    # Fetch user balance
    cursor.execute("SELECT balance FROM users WHERE username=?", (username,))
    try:
        balance = cursor.fetchone()[0]
    except:
        return redirect('/')

    # Vulnerable: Comments expose the username field, making brute forcing a lot easier
    cursor.execute("SELECT username, content FROM comments")
    comments = cursor.fetchall()
    # Check if the user is an admin
    is_admin = True if username == 'admin' else False

    return render_template('dashboard.html', username=username, balance=balance, is_admin=is_admin, comments=comments)

# Add a comment
@app.route('/add_comment', methods=['POST'])
def add_comment():
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')
    
    content = request.form['content']

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (username, content))
    conn.commit()

    return redirect('/dashboard')


@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')
    
    # Vulnerable: Username parameter is attacker-controlled, and can be manipulated to delete other accounts by username
    target_username = request.args.get('username')  

    if not target_username:
        return redirect('/')
    
    if target_username == "admin":
        return render_template('error.html', error="No deleting admin user :p")
    
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Delete the user account based on the provided username
        cursor.execute("DELETE FROM users WHERE username=?", (target_username,))
        conn.commit()

        response = make_response(redirect('/'))
        response.set_cookie('Auth', '', expires=0)
        return response
    except Exception as e:
        # Handle any errors that occur during the deletion process
        render_template('register.html', error="User not found")


@app.route('/insert', methods=['GET', 'POST'])
def insert():
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    # Get the base64 encoded data from the form
    if request.method == 'POST':
        # try:
            encoded_data = request.form.get('data')
            decoded_data = base64.b64decode(encoded_data.encode('utf-8'))  # Convert to bytes and then decode base64
            # Vulnerable: unpickling unsanitized user input
            pickle.loads(decoded_data)
            return render_template('pickle.html')
        # except:
        #     return render_template('error.html', error="Pickled data must be sent.")
    else:
        return render_template('error.html', error="This is an internal POST endpoint used for unpickling base64 databases.")

    
# Transfer money page
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    if request.method == 'POST':
        recipient = request.form['recipient']
        try: 
            amount = float(request.form['amount'])
        except:
            return render_template('transfer.html', error='Enter a number')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT balance FROM users WHERE username=?", (username,))
        sender_balance = cursor.fetchone()[0]
        # Vulnerable: no check on negative amounts
        if sender_balance >= amount:
            cursor.execute("SELECT balance FROM users WHERE username=?", (recipient,))

            recipient_data = cursor.fetchone()
            if recipient_data:
                recipient_balance = recipient_data[0]
                
                # Update recipient's balance
                cursor.execute("UPDATE users SET balance=? WHERE username=?", (recipient_balance + amount, recipient))

                # Update sender's balance
                cursor.execute("UPDATE users SET balance=? WHERE username=?", (sender_balance - amount, username))

                conn.commit()
                return redirect('/dashboard')
            else:
                # Vulnerable: exposes if a username is valid, allowing for username enumeration
                return render_template('transfer.html', error='Receiver Account Not Found')
        else:
            return render_template('transfer.html', error='You are too broke for that (womp womp)')
    return render_template('transfer.html')

# Admin page
@app.route('/admin')
def admin():
    # Vulnerable: checking administrative permissions via weak auth cookie
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    if username == 'admin':
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
    # Vulnerable: checking administrative permissions via weak auth cookie
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')


    if username == 'admin':
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



# Unauthenticated Pages

@app.route('/', methods=['GET', 'POST'])
def serve_file():
    # Vulnerable: getting arbitrary file path from user and serving the file
    file_param = request.args.get('page')

    # Check if the 'file' parameter is present
    if file_param:
        # Ensure user is authed since this originates from the authenticated stocks page

        b64_username = request.cookies.get('Auth') 
        username = validate_user(b64_username)
        if not username:
            return redirect('/')

        try:
            # Serve the specified file
            return send_file(file_param)
        except Exception as e:
            # Handle exceptions, log, or customize error response
            return f"Error: {str(e)}"
    else:
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
        # For example: SELECT * FROM users WHERE username='' OR 1=1;-- 'AND password = '';
        query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                
                response = make_response(redirect('/dashboard'))
                
                db_username = user[1]

                # Vulnerable: Using username in base64 (easily decode-able) as session token
                base64_auth = base64.b64encode(db_username.encode('utf-8')).decode('utf-8')

                # Vulnerable: Cookie does not have HttpOnly set to true, meaning it can be access and stolen via attacker-injected javascript
                response.set_cookie('Auth', base64_auth)
                response.set_cookie('Username', username)
                return response
            else:
                error = 'Invalid username or password'
        except sqlite3.Error as e:
            error = f"{str(e)}"
    return render_template('login.html', error=error)

# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        balance = 100
        conn = get_db()
        cursor = conn.cursor()
        if password == "" or username == "":
            return render_template('register.html', error='Both fields must not be empty')
        try:
            # Vulnerable: passwords stored in plaintext in database
            cursor.execute("INSERT INTO users (username, password, balance) VALUES (?, ?, ?)", (username, password, balance))
            conn.commit()

            response = make_response(redirect('/dashboard'))
            # Vulnerable: Using username in base64 (easily decode-able) as session token
            base64_auth = base64.b64encode(username.encode('utf-8')).decode('utf-8')

            # Vulnerable: Cookie is not http-only, meaning it can be access and stolen via attacker-injected javascript
            response.set_cookie('Auth', base64_auth)
            response.set_cookie('Username', username)

            return response
        except sqlite3.IntegrityError:
            # Vulnerable: exposes if a username is valid, allowing for username enumeration
            return render_template('register.html', error='Username already exists')
    return render_template('register.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    # Vulnerable: This input has only been sanitized client-side
    email = request.form.get('email')

    # Vulnerable: This is simulating what an actual server would do 
    # (essentially a placeholder for a real mail command)
    # and is vulnerable to command injection into subprocess.run
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
    # Clear the Auth cookie
    # Vulnerable: previous sessions not invalidated (mainly because they are the same each time)
    response = make_response(redirect('/'))
    response.set_cookie('Auth', '', expires=0)
    return response


if __name__ == '__main__':
    init_db()

    parser = argparse.ArgumentParser(description='Run the Flask application.')
    parser.add_argument('mode', choices=['open', 'closed'], help='Specify whether the application should be open to all network interfaces or closed to localhost.')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Optional - port number to run the application on. Default is 5000.')

    args = parser.parse_args()

    host = '0.0.0.0' if args.mode == 'open' else '127.0.0.1'
    port = args.port

    # Vulnerable: debugging enabled, revealing sensitive source code, a python console, and app information
    app.run(debug=True, port=port, host=host)

