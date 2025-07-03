import boto3
from flask import Flask, render_template, redirect, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
from botocore.exceptions import ClientError
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Flask-Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
mail = Mail(app)

# AWS SNS configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
sns_client = boto3.client('sns', region_name=AWS_REGION)
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')  # Set this in your environment

def send_sns_notification(message, subject=None):
    if not SNS_TOPIC_ARN:
        return False
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject or 'Notification'
        )
        return True
    except Exception as e:
        print(f"SNS Error: {e}")
        return False

def send_email(to, subject, body):
    try:
        msg = Message(subject, recipients=[to], body=body)
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email Error: {e}")
        return False

# DynamoDB setup
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
users_table = dynamodb.Table('users')
carts_table = dynamodb.Table('carts')
orders_table = dynamodb.Table('orders')

def get_user(username):
    try:
        response = users_table.get_item(Key={'username': username})
        return response.get('Item')
    except ClientError:
        return None

def add_user(username, email, password_hash):
    try:
        users_table.put_item(Item={
            'username': username,
            'email': email,
            'password': password_hash
        }, ConditionExpression='attribute_not_exists(username)')
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return False
        raise

def get_cart(username):
    response = carts_table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key('username').eq(username)
    )
    return response.get('Items', [])

def add_to_cart(username, name, price, image):
    # Try to update qty, if not exists, put new
    try:
        carts_table.update_item(
            Key={'username': username, 'name': name},
            UpdateExpression='SET qty = if_not_exists(qty, :zero) + :inc, price=:price, image=:image',
            ExpressionAttributeValues={':inc': 1, ':zero': 0, ':price': price, ':image': image},
            ReturnValues='UPDATED_NEW'
        )
    except ClientError as e:
        raise

def remove_from_cart(username, name):
    carts_table.delete_item(Key={'username': username, 'name': name})

def clear_cart(username):
    items = get_cart(username)
    for item in items:
        carts_table.delete_item(Key={'username': username, 'name': item['name']})

def get_orders(username):
    response = orders_table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key('username').eq(username)
    )
    return response.get('Items', [])

def add_order(username, name, price, image, qty):
    orders_table.put_item(Item={
        'username': username,
        'name': name,
        'price': price,
        'image': image,
        'qty': qty
    })

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and check_password_hash(user['password'], password):
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
        if get_user(username) or any(u.get('email') == email for u in users_table.scan().get('Items', [])):
            error = 'Username or email already exists.'
            return render_template('signup.html', error=error)
        hashed_password = generate_password_hash(password)
        if add_user(username, email, hashed_password):
            flash('Signup successful! Please log in.')
            send_sns_notification(f'New user signed up: {username}', subject='New Signup')
            send_email(email, 'Welcome to HomeMade!', f'Thank you for signing up, {username}!')
            return redirect(url_for('login'))
        else:
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
    cart_items = get_cart(username)
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
    add_to_cart(username, name, price, image)
    flash(f"{name} added to cart!")
    return redirect(request.referrer or url_for('home'))

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    item_name = request.form['name']
    remove_from_cart(username, item_name)
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
        username = session['user']
        cart = get_cart(username)
        for item in cart:
            add_order(username, item['name'], item['price'], item['image'], item['qty'])
        clear_cart(username)
        send_sns_notification(f'Order placed by {username}', subject='Order Success')
        send_email(email, 'Order Confirmation', f'Your order has been placed, {username}!')
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
    user_orders = get_orders(username)
    return render_template('my_orders.html', orders=user_orders)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
