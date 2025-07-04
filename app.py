from flask import Flask, render_template, redirect, url_for, request, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Database setup
conn = sqlite3.connect('users.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)''')
conn.commit()

# Orders database setup
orders_conn = sqlite3.connect('orders.db', check_same_thread=False)
orders_c = orders_conn.cursor()
orders_c.execute('''CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    price INTEGER NOT NULL,
    image TEXT NOT NULL,
    qty INTEGER NOT NULL
)''')
orders_conn.commit()

# Carts database setup
carts_conn = sqlite3.connect('carts.db', check_same_thread=False)
carts_c = carts_conn.cursor()
carts_c.execute('''CREATE TABLE IF NOT EXISTS carts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    price INTEGER NOT NULL,
    image TEXT NOT NULL,
    qty INTEGER NOT NULL
)''')
carts_conn.commit()

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        c.execute('SELECT password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user and check_password_hash(user[0], password):
            session['user'] = username
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        try:
            c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                      (username, email, hashed_password))
            conn.commit()
            flash('Signup successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = 'Username or email already exists.'
            return render_template('signup.html', error=error)
    return render_template('signup.html')

@app.route('/home')
def home():
    if 'user' in session:
        return render_template('home.html', username=session['user'])
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/cart')
def cart():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    carts_c.execute('SELECT name, price, image, qty FROM carts WHERE username = ?', (username,))
    cart_items = [
        {'name': row[0], 'price': row[1], 'image': row[2], 'qty': row[3]}
        for row in carts_c.fetchall()
    ]
    return render_template('cart.html', cart_items=cart_items)

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'user' not in session:
        flash("You need to login first")
        return redirect(url_for('login'))

    username = session['user']
    name = request.form['name']
    price = int(request.form['price'])
    image = request.form['image']

    # Check if item already in cart
    carts_c.execute('SELECT qty FROM carts WHERE username = ? AND name = ?', (username, name))
    row = carts_c.fetchone()
    if row:
        carts_c.execute('UPDATE carts SET qty = qty + 1 WHERE username = ? AND name = ?', (username, name))
    else:
        carts_c.execute('INSERT INTO carts (username, name, price, image, qty) VALUES (?, ?, ?, ?, ?)',
                        (username, name, price, image, 1))
    carts_conn.commit()
    flash(f"{name} added to cart!")
    return redirect(request.referrer or url_for('home'))

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    item_name = request.form['name']
    carts_c.execute('DELETE FROM carts WHERE username = ? AND name = ?', (username, item_name))
    carts_conn.commit()
    flash(f"{item_name} removed from cart.")
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user' not in session:
        flash("You must be logged in to checkout.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        phone = request.form['phone']
        payment = request.form['payment']

        if not name or not address or not phone or not payment:
            error = "All fields are required."
            return render_template('checkout.html', error=error)

        # Save order to orders.db
        username = session['user']
        carts_c.execute('SELECT name, price, image, qty FROM carts WHERE username = ?', (username,))
        cart = [
            {'name': row[0], 'price': row[1], 'image': row[2], 'qty': row[3]}
            for row in carts_c.fetchall()
        ]
        for item in cart:
            orders_c.execute('INSERT INTO orders (username, name, price, image, qty) VALUES (?, ?, ?, ?, ?)',
                             (username, item['name'], item['price'], item['image'], item['qty']))
        orders_conn.commit()
        # Clear user's cart after order
        carts_c.execute('DELETE FROM carts WHERE username = ?', (username,))
        carts_conn.commit()
        return redirect(url_for('order_success'))

    return render_template('checkout.html')

@app.route('/order_success')
def order_success():
    return render_template('order_success.html')

@app.route('/snacks')
def snacks():
    return render_template('snacks.html')

@app.route('/veg')
def veg():
    return render_template('veg.html')

@app.route('/nveg')
def nveg():
    return render_template('nveg.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/my_orders')
def my_orders():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    orders_c.execute('SELECT name, price, image, qty FROM orders WHERE username = ?', (username,))
    orders = [
        {'name': row[0], 'price': row[1], 'image': row[2], 'qty': row[3]}
        for row in orders_c.fetchall()
    ]
    return render_template('my_orders.html', orders=orders)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
