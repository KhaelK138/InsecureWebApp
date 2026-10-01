from flask import Flask, request, render_template, render_template_string, redirect, send_file, make_response
from datetime import timedelta
import numbers
import sqlite3
import subprocess
import base64
import pickle
import argparse
import uuid
import os

# Vulnerable: No CSRF protection on any forms, allowing attackers to forge requests on behalf of authenticated users
app = Flask(__name__)

# Vulnerable: Plaintext Secrets
app.secret_key = 'super_secret_auth_key'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = timedelta(days=1)

# Path to SQLite database
DATABASE = 'database.db'

# Initialize database schema
def init_db():
    if os.path.exists("database.db"):
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
            cursor.execute("INSERT INTO users (username, password, balance, role) VALUES (?, ?, ?, ?)", (admin_username, admin_password, 1338, "admin"))
            # Not really vulnerable; these users are just examples and would normally be created through the app
            cursor.execute("INSERT INTO users (username, password, balance, profile_pic) VALUES (?, ?, ?, ?)", ("johndoe", "Password123!", -9899, "/static/uploads/johndoe.jpg"))
            cursor.execute("INSERT INTO users (username, password, balance, profile_pic) VALUES (?, ?, ?, ?)", ("haxor", "Pr0v4b1yIns3cur3!", 9999, "/static/uploads/haxor.jpg"))

        # Seed some transaction history
        cursor.execute("SELECT COUNT(*) FROM transactions")
        if not cursor.fetchone()[0]:
            cursor.execute("INSERT INTO transactions (sender, recipient, amount) VALUES (?, ?, ?)", ("johndoe", "haxor", 10000))
            cursor.execute("INSERT INTO transactions (sender, recipient, amount) VALUES (?, ?, ?)", ("admin", "johndoe", 1))

        # Create comments
        comment_username_1 = "johndoe"
        comment_content_1 = "All my money disappeared. I'm literally in debt. 0/10"
        comment_username_2 = "haxor"
        comment_content_2 = "<b>This text is bold... interesting...</b>"
        cursor.execute("SELECT COUNT(*) FROM comments")
        if not cursor.fetchone()[0]:
            cursor.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (comment_username_1, comment_content_1))
            cursor.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (comment_username_2, comment_content_2))

        cursor.execute("SELECT COUNT(*) FROM ratings")
        if not cursor.fetchone()[0]:
            fake_ratings = [1]*15 + [2]*15 + [3]*13 + [4]*7 + [5]*3
            for i, r in enumerate(fake_ratings):
                cursor.execute("INSERT INTO ratings (username, rating) VALUES (?, ?)", (f"customer{i+1}", r))

        cursor.execute("SELECT COUNT(*) FROM support_tickets")
        if not cursor.fetchone()[0]:
            cursor.execute("INSERT INTO support_tickets (username, subject, message) VALUES (?, ?, ?)", ("johndoe", "Missing funds", "Where did my money go? I had $10000 yesterday."))
            cursor.execute("INSERT INTO support_tickets (username, subject, message) VALUES (?, ?, ?)", ("haxor", "Feature request", "Can you add a crypto section?"))

        db.commit()


# Connect to the SQLite database
def get_db():
    db = sqlite3.connect(DATABASE)
    return db

def is_admin(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    return result and result[0] == 'admin'

@app.context_processor
def inject_user_context():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if username:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT role, profile_pic FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        pic = result[1] if result and result[1] else '/static/default_profile.svg'
        return {'is_admin': result and result[0] == 'admin', 'profile_pic': pic}
    return {'is_admin': False, 'profile_pic': '/static/default_profile.svg'}

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

    return render_template('dashboard.html', username=username, balance=balance)

@app.route('/reviews')
def reviews():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT c.username, c.content, COALESCE(NULLIF(u.display_name, ''), c.username), COALESCE(NULLIF(u.profile_pic, ''), '/static/default_profile.svg') FROM comments c LEFT JOIN users u ON c.username = u.username")
    comments = cursor.fetchall()
    cursor.execute("SELECT AVG(rating), COUNT(*) FROM ratings")
    avg_result = cursor.fetchone()
    avg_rating = round(avg_result[0], 1) if avg_result[0] is not None else 0
    num_ratings = avg_result[1]
    cursor.execute("SELECT rating FROM ratings WHERE username=?", (username,))
    user_rating = cursor.fetchone()
    user_rating = user_rating[0] if user_rating else None
    return render_template('reviews.html', username=username, comments=comments, avg_rating=avg_rating, num_ratings=num_ratings, user_rating=user_rating)


@app.route('/rate', methods=['POST'])
def rate():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    try:
        # Vulnerable: No server-side range validation on rating, accepting any integer value including extreme negatives
        rating = int(request.form.get('rating', 0))
    except:
        return redirect('/reviews')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO ratings (username, rating) VALUES (?, ?)", (username, rating))
    conn.commit()
    return redirect('/reviews')


# Add a comment
@app.route('/add_comment', methods=['POST'])
def add_comment():
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')
    
    # Vulnerable: Comment content is not sanitized and the template renders it with |safe, enabling stored XSS
    content = request.form['content']
    if not content:
        return render_template('error.html', error="Gotta submit something pal")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (username, content))
    conn.commit()

    return redirect('/reviews')


# Vulnerable: Destructive action performed via GET request, exploitable through a simple link or image tag
@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')
    
    # Vulnerable: Destructive action via GET with no CSRF token -- an attacker can embed <img src="/delete_account"> to delete a victim's account when they visit a malicious page
    if username == "admin":
        return render_template('error.html', error="No deleting admin user :p")

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM users WHERE username=?", (username,))
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
        # Vulnerable: Balance read and update are not atomic, allowing race condition double-spend via concurrent requests
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

                cursor.execute("INSERT INTO transactions (sender, recipient, amount) VALUES (?, ?, ?)", (username, recipient, amount))
                conn.commit()
                return redirect('/dashboard')
            else:
                # Vulnerable: exposes if a username is valid, allowing for username enumeration
                return render_template('transfer.html', error='Receiver Account Not Found')
        else:
            return render_template('transfer.html', error='You are too broke for that (womp womp)')
    return render_template('transfer.html')

@app.route('/transactions')
def transactions():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    conn = get_db()
    cursor = conn.cursor()

    # Vulnerable: user_id query parameter is attacker-controlled, allowing viewing any user's transaction history (IDOR)
    user_id = request.args.get('user_id')
    if not user_id:
        cursor.execute("SELECT id FROM users WHERE username=?", (username,))
        user_id = cursor.fetchone()[0]

    cursor.execute("SELECT username FROM users WHERE id=?", (user_id,))
    result = cursor.fetchone()
    if not result:
        return render_template('error.html', error="User not found")
    target_username = result[0]

    cursor.execute("SELECT * FROM transactions WHERE sender=? OR recipient=? ORDER BY timestamp DESC", (target_username, target_username))
    txns = cursor.fetchall()

    return render_template('transactions.html', transactions=txns, target_user=target_username, user_id=user_id)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        # Vulnerable: All form fields are dynamically mapped to SQL column names, allowing mass assignment (e.g. role=admin) to escalate privileges
        fields = {}
        for key in request.form:
            if key and request.form[key]:
                fields[key] = request.form[key]

        if fields:
            set_clause = ', '.join(f"{k}=?" for k in fields)
            values = list(fields.values()) + [username]
            cursor.execute(f"UPDATE users SET {set_clause} WHERE username=?", values)
            conn.commit()

        return redirect('/profile')

    cursor.execute("SELECT display_name, email FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    display_name = user[0] if user[0] else username
    upload_success = request.args.get('upload_success')
    upload_error = request.args.get('upload_error')
    return render_template('profile.html', username=username, display_name=display_name, email=user[1], upload_success=upload_success, upload_error=upload_error)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    if request.method == 'POST':
        # Vulnerable: No file type validation, original filename used directly, allowing upload of malicious files, path traversal, and overwriting existing files
        file = request.files.get('file')
        if not file or file.filename == '':
            return redirect('/profile?upload_error=No+file+selected')

        filepath = os.path.join('static/uploads', file.filename)
        file.save(filepath)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET profile_pic=? WHERE username=?", (f"/static/uploads/{file.filename}", username))
        conn.commit()

        return redirect('/profile?upload_success=File+uploaded')

    return redirect('/profile')

@app.route('/support', methods=['GET', 'POST'])
def support():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    if request.method == 'POST':
        subject = request.form.get('subject', '')
        message = request.form.get('message', '')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO support_tickets (username, subject, message) VALUES (?, ?, ?)", (username, subject, message))
        conn.commit()
        ticket_id = cursor.lastrowid
        return redirect(f'/support?ticket={ticket_id}')

    # Vulnerable: Ticket ID from query parameter is not checked against the logged-in user, allowing any user to view any ticket (IDOR)
    ticket_id = request.args.get('ticket')
    if ticket_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT subject, username FROM support_tickets WHERE id=?", (ticket_id,))
        ticket = cursor.fetchone()
        if ticket:
            # Vulnerable: Ticket subject is concatenated into render_template_string, allowing server-side template injection (SSTI) and remote code execution
            return render_template_string('<h1>Thank you, ' + ticket[1] + '</h1><p>Your ticket regarding "' + ticket[0] + '" has been received. We will respond shortly.</p><a href="/support">Back to Support</a>')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, subject, message, created_at, response FROM support_tickets WHERE username=? ORDER BY id DESC", (username,))
    tickets = cursor.fetchall()
    return render_template('support.html', tickets=tickets)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    if request.method == 'POST':
        token = str(uuid.uuid4())
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO password_reset_tokens (username, token) VALUES (?, ?)", (username, token))
        conn.commit()
        return redirect(f'/reset_password?token={token}')

    return redirect('/profile')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    token = request.args.get('token', '')
    if request.method == 'POST':
        token = request.form.get('token', token)
        new_password = request.form.get('password', '')
        # Vulnerable: username comes from the form and can be changed to reset any user's password
        target_username = request.form.get('username', '')
        if not new_password:
            return render_template('reset_password.html', token=token, username=username, error="Password cannot be empty")

        conn = get_db()
        cursor = conn.cursor()
        # Vulnerable: Token is not checked for expiration, allowing old tokens to be reused indefinitely
        cursor.execute("SELECT id FROM password_reset_tokens WHERE token=?", (token,))
        result = cursor.fetchone()
        if result:
            cursor.execute("UPDATE users SET password=? WHERE username=?", (new_password, target_username))
            cursor.execute("DELETE FROM password_reset_tokens WHERE token=?", (token,))
            conn.commit()
            return redirect('/dashboard')
        else:
            return render_template('reset_password.html', token=token, username=username, error="Invalid or expired token")

    return render_template('reset_password.html', token=token, username=username)

# Admin page
@app.route('/admin')
def admin():
    # Vulnerable: checking administrative permissions via weak auth cookie
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    if is_admin(username):
        conn = get_db()
        cursor = conn.cursor()
        # Vulnerable: admins should not be able to see all user's passwords
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        return render_template('admin.html', users=users)
    else:
        return render_template('error.html', error="You are not an admin (I think)")
        


@app.route('/admin/tickets')
def admin_tickets():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    if is_admin(username):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, subject, message, response, created_at FROM support_tickets ORDER BY id DESC")
        tickets = cursor.fetchall()
        return render_template('admin_tickets.html', tickets=tickets)
    else:
        return render_template('error.html', error="You are not an admin (I think)")


@app.route('/admin/respond_ticket', methods=['POST'])
def respond_ticket():
    b64_username = request.cookies.get('Auth')
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    if is_admin(username):
        ticket_id = request.form.get('ticket_id')
        response = request.form.get('response', '')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE support_tickets SET response=? WHERE id=?", (response, ticket_id))
        conn.commit()
        return redirect('/admin/tickets')
    else:
        return redirect('/')


# Admin update balance
@app.route('/admin/update_balance', methods=['POST'])
def update_balance():
    # Vulnerable: checking administrative permissions via weak auth cookie
    b64_username = request.cookies.get('Auth') 
    username = validate_user(b64_username)
    if not username:
        return redirect('/')

    if is_admin(username):
        username = request.form['username']
        new_balance = request.form['balance']
        if not isinstance(new_balance, numbers.Number):
            return render_template('error.html', error="What were you even trying to do???")
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
            # Vulnerable: Raw exception message returned to the user, leaking file paths and server internals
            return f"Error: {str(e)}"

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
                # Vulnerable: 'next' parameter used as redirect target without validation, allowing open redirect to external malicious sites
                next_url = request.args.get('next') or request.form.get('next') or '/dashboard'
                response = make_response(redirect(next_url))

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
            # Vulnerable: Raw SQL error messages returned to the user, leaking database structure and query details
            error = f"{str(e)}"
    return render_template('index.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Vulnerable: 'next' parameter passed through without validation, allowing open redirect to external malicious sites
    return redirect('/' + ('?next=' + request.args.get('next') if request.args.get('next') else ''))

# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        # Vulnerable: Allow weak application passwords
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
        subscribe_msg = f"Success: {result.stdout.strip()}"
    else:
        subscribe_msg = f"Error: {result.stderr.strip()}"

    return render_template('index.html', subscribe_msg=subscribe_msg)


# Logout route
@app.route('/logout')
def logout():
    # Clear the Auth cookie
    # Vulnerable: previous sessions not invalidated (mainly because they are the same each time)
    response = make_response(redirect('/'))
    response.set_cookie('Auth', '', expires=0)
    return response


if __name__ == '__main__':
    if not os.environ.get('WERKZEUG_RUN_MAIN'):
        init_db()

    parser = argparse.ArgumentParser(description='Run the Flask application.')
    parser.add_argument('mode', choices=['open', 'closed'], help='Specify whether the application should be open to all network interfaces or closed to localhost.')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Optional - port number to run the application on. Default is 5000.')

    args = parser.parse_args()

    host = '0.0.0.0' if args.mode == 'open' else '127.0.0.1'
    port = args.port

    # Vulnerable: debugging enabled, revealing sensitive source code, a python console, and app information
    app.run(debug=True, port=port, host=host)

