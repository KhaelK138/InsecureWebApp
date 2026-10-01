# Vulnerable Basic Banking Application

This is a vulnerable banking application, meant for practicing exploitation of web vulnerabilities. 

Don't host this app publicly without ensuring anyone that can access it is trusted. You'll have a bad day.

### INSTALLATION

Clone the repo, and make sure you have all the required python libraries installed (flask, sqlite3, pickle, flask_bcrypt, validate_email)

### USAGE

Insecure Application:
- Run `python3 app.py closed` to host the app locally, accessible only at 127.0.0.1:5000
- Run `python3 app.py open` to open the app to all network interfaces, accessible at {your ip}:5000

The application can be configured to run on a different port with the flag `-p {port}`.


