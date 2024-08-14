from flask import Flask, render_template, request, redirect, url_for, flash, session
import pymysql
from flask_mail import Mail, Message
import random
import string

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
    'user': 'your_db_user',
    'password': 'your_db_password',
    'host': 'localhost',
    'database': 'mydatabase'
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

        # Hash the password before storing it
        hashed_password = generate_password_hash(password, method='sha256')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password, email) VALUES (%s, %s, %s)',
                       (username, hashed_password, email))

        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('home'))

    return render_template('add_user.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = %s', (username,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()

        if result and check_password_hash(result[0], password):
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']

        # Hash the new password before storing it
        hashed_password = generate_password_hash(new_password, method='sha256')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = %s WHERE username = %s', (hashed_password, username))
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
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))  # Generate a random password

        # Hash the new password before storing it in the database
        hashed_password = generate_password_hash(new_password, method='sha1')  # Note: SHA-1 is used here

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = %s WHERE email = %s', (hashed_password, email))
        conn.commit()
        cursor.close()
        conn.close()

        # Send the new password via email
        msg = Message('Your New Password', sender='your_email@example.com', recipients=[email])
        msg.body = f'Your new password is: {new_password}'
        mail.send(msg)

        flash('A new password has been sent to your email address.', 'success')
        return redirect(url_for('login'))

    return render_template('generate_new_password.html')


if __name__ == '__main__':
    app.run(debug=True)
