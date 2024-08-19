from flask import Flask, render_template, request, redirect, url_for, flash, session
import pymysql
import hashlib
import hmac
import os
from flask_mail import Mail, Message
import random
import string
import passwordRules
from passwordRules import parse_ini_file
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management and flashing messages

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.example.com'  # Replace with your SMTP server
app.config['MAIL_PORT'] = 587  # Replace with your SMTP port
app.config['MAIL_USERNAME'] = 'your_email@example.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your_email_password'  # Replace with your email password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# Database connection details
db_config = {
    'user': 'root',
    'password': '123456',
    'host': 'localhost',
    'database': 'computersecurity'
}

def get_db_connection():
    return pymysql.connect(**db_config)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Establish a connection to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the username already exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = %s', (username,))
        user_exists = cursor.fetchone()[0] > 0

        if user_exists:
            #todo:
            flash('Username already exists. Please choose a different username.', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('add_user'))

        # Step 1: Generate a salt
        salt = os.urandom(16)  # 16 bytes of random salt

        # Step 2: Create HMAC hash using the salt and the password
        hashed_password = hmac.new(salt, password.encode(), hashlib.sha256).hexdigest()

        # Combine the salt and the hashed password for storage
        salt_and_hashed_password = f'{salt.hex()}${hashed_password}'



        # Insert the user into the `users` table
        cursor.execute('INSERT INTO users (username, password, email, salt) VALUES (%s, %s, %s, %s)',
                       (username, salt_and_hashed_password, email, salt))
        conn.commit()

        # Retrieve the `userid` of the newly inserted user
        userid = cursor.lastrowid

        # Insert the hashed password into the `passwords` table
        cursor.execute(
            'INSERT INTO passwords (id, password, passwordHistoryIndex) VALUES (%s, %s, %s)',
            (userid, salt_and_hashed_password, 0)
        )

        # Insert the new user into the database
        #cursor.execute('INSERT INTO users (username, password, email, salt) VALUES (%s, %s, %s, %s)',
         #              (username, salt_and_hashed_password, email, salt))

        """
        #alerting the user that history condition is not filled
        if history_result==False:
            return False
        #history_result=passwordRules.check_history(salt_and_hashed_password)
        #write the hashed_password to the historyPassword.ini file
        # Open the file in append mode
        with open('historyPasswords.ini', 'a') as file:
            # Write the password and add a newline
            file.write(f"{salt_and_hashed_password}\n")
        """

        conn.commit()
        cursor.close()
        conn.close()

        flash('User added successfully.','success')
        return redirect(url_for('home'))

    return render_template('add_user.html')

#committing "decryption" using salt to get the original passowrd
def verify_password(stored_hash, password):
    # Split the stored hash into the salt and the actual hash
    salt, actual_stored_hash = stored_hash.split('$')

    # Convert the salt back to bytes (if it was stored as hex)
    salt = bytes.fromhex(salt)

    # Generate the hash with the provided password and extracted salt
    generated_hash = hmac.new(salt, password.encode(), hashlib.sha256).hexdigest()

    # Compare the generated hash with the stored hash
    return generated_hash == actual_stored_hash


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT p.password, u.salt, u.id FROM users u JOIN passwords p ON u.id = p.id WHERE u.username = %s;',(username))

        #cursor.execute('SELECT password, salt FROM users WHERE username = %s', (username,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        #todo: to remove salt from the database
        passwordFromDataBase=result[0] #getting the password from database
        saltFromDataBase=result[1] #getting the salt from dataBase
        user_id = result[2]
        if result and verify_password(passwordFromDataBase, password):
            flash('Login successful!', 'success')
            # Store the username in the session
            session['user_id'] = user_id
            return redirect(url_for('add_customer'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        conn = get_db_connection()
        cursor = conn.cursor()
        # Check password history
        cursor.execute('SELECT p.password, p.passwordHistoryIndex, u.id FROM password p JOIN user u ON p.id = u.id WHERE u.username = %s ORDER BY p.passwordHistoryIndex DESC;', (username))
        result = cursor.fetchall()
        if not result:
            flash('User name does not exist.', 'danger')
        else:
            newest_index = result[0][1]
            user_id = result[0][2]

            for item in result[0:passwordRules.history]:
                password = item[0]
                if verify_password(password, new_password):
                    flash(f'This password was used in your last {passwordRules.history} passwords, try another one.', 'danger')

            # Step 1: Generate a salt
            salt = os.urandom(16)  # 16 bytes of random salt

            # Step 2: Create HMAC hash using the salt and the password
            hashed_password = hmac.new(salt, new_password.encode(), hashlib.sha256).hexdigest()

            # Combine the salt and the hashed password for storage
            salt_and_hashed_password = f'{salt.hex()}${hashed_password}'

            # Insert the hashed password into the `passwords` table
            cursor.execute(
                'INSERT INTO passwords (id, password, passwordHistoryIndex) VALUES (%s, %s, %s)',
                (user_id, salt_and_hashed_password, newest_index + 1)
            )

            # cursor.execute('UPDATE users SET password = %s WHERE username = %s', (hashed_password, username))
            conn.commit()
            cursor.close()
            conn.close()

            flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/add_customer', methods=['GET', 'POST'])
def add_customer():
    """
    Render the form to add a new customer or handle form submission to create a new customer.
    Only accessible after logging in.
    """
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        customer_name = request.form['customer_name']
        user_id = session['user_id']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO customers (customer_name, user_id) VALUES (%s, %s)', (customer_name, user_id))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Customer added successfully!', 'success')
        return redirect(url_for('add_customer'))

    return render_template('add_customer.html')


@app.route('/generate_new_password', methods=['GET', 'POST'])
def generate_new_password():
    """
    Render the page to request a new password or handle the password generation form submission.
    """
    if request.method == 'POST':
        email = request.form['email']
        # new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))  # Generate a random password

        # Hash the new password before storing it in the database
        # hashed_password = generate_password_hash(new_password, method='sha1')  # Note: SHA-1 is used here
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

        # Store the key in the session
        session['reset_key'] = key
        session['email'] = email

        # conn = get_db_connection()
        # cursor = conn.cursor()
        # cursor.execute('UPDATE users SET password = %s WHERE email = %s', (hashed_password, email))
        # conn.commit()
        # cursor.close()
        # conn.close()

        # Send the key via email
        msg = Message('Your Password Reset Key', sender='your_email@example.com', recipients=[email])
        msg.body = f'Your password reset key is: {key}'
        mail.send(msg)

        flash('A reset key has been sent to your email address.', 'success')
        return redirect(url_for('verify_key'))

    return render_template('generate_new_password.html')


@app.route('/verify_key', methods=['GET', 'POST'])
def verify_key():
    if request.method == 'POST':
        key = request.form['key']
        stored_key = session.get('reset_key')

        if key == stored_key:
            return redirect(url_for('forgot_password'))
        else:
            flash('Invalid key. Please try again.', 'error')

    return render_template('verify_key.html')


if __name__ == '__main__':
    app.run(debug=True)
