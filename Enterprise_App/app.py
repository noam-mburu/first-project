from flask import Flask , render_template, flash, redirect, url_for, session, logging, request
from flask.globals import request
from flask.signals import message_flashed
#from misc.data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt #for password encryption
from functools import wraps

#instance of flask class
app = Flask(__name__)

#Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'noam'
app.config['MYSQL_PASSWORD'] = '1605'
app.config['MYSQL_DB'] = 'EnterpriseApp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#Initialize MySQL
mysql = MySQL(app)

#Home
@app.route('/')
def home():
    return render_template('home.html')

#About
@app.route('/about')
def about():
    return render_template('about.html')

#Contact
@app.route('/contact')
def contact():
    return render_template('contact.html')

#Register Form Class
class RegisterForm(Form):
    name = StringField('Name' , [validators.Length(min = 1 , max = 50)])
    username = StringField('Username', [validators.Length(min=3, max = 29 )])
    phone_no = StringField('Phone Number', [validators.Length(min=6 , max =20)])
    address= StringField('Address', [validators.Length(min=6 , max =200)])
    acc_no= StringField('Account Number', [validators.Length(max =30)])
    card_no= StringField('Card Number', [validators.Length(max =30)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message = "Passwords do not match ")
    ])
    confirm = PasswordField('Confrim Password')

#Customer Register
@app.route('/register', methods=['GET','POST']) #defining for posting data to website and getting data from website
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        username = form.username.data
        phone_no = form.phone_no.data
        address = form.address.data
        acc_no = form.acc_no.data
        card_no = form.card_no.data
        password = sha256_crypt.encrypt(str(form.password.data))

        #Cursor
        cur = mysql.connection.cursor()
        
        #Execute query
        cur.execute("INSERT INTO customers(name, username, phone_no, address, password) VALUES(%s, %s, %s, %s, %s)", (name, username, phone_no, address, password))
        if len(acc_no) > 0:
            cur.execute('INSERT INTO contract(acc_no, username) VALUES (%s, %s)',(acc_no, username))
        elif len(card_no) > 0:
            cur.execute('INSERT INTO others(card_no, username) VALUES (%s, %s)',(card_no, username))

        #Commit to DB
        mysql.connection.commit()

        #Close Connection
        cur.close()

        flash("You are now registed and can log in" , 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form = form)

#Customer Login
@app.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        #Get form fields
        username = request.form['username']
        password_cand = request.form['password']

        #Create Cursor
        cur = mysql.connection.cursor()

        #Get user by username
        result = cur.execute("SELECT * FROM customers WHERE username = %s", [username])

        if result > 0:
            #Get stored hash
            data = cur.fetchone()
            password = data['password']

            #Compare Passwords
            if sha256_crypt.verify(password_cand, password):
                app.logger.info('PASSWORD MATCH')
                #Passed
                session['customer_logged_in'] = True
                session['username'] = username

                flash("You are now logged in" , 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                app.logger.info('PASSWORD NOT MATCHED')
                return render_template('login.html', error = error)
            
            #close connection
            cur.close()

        else:
            error = 'Customer Username not found'
            return render_template('login.html', error = error)

    return render_template('login.html')

#Admin Login
@app.route('/admin_login', methods = ['GET','POST'])
def admin_login():
    if request.method == 'POST':
        #Get form fields
        username = request.form['username']
        password_cand = request.form['password']

        #Create Cursor
        cur = mysql.connection.cursor()

        #Get user by username
        result = cur.execute("SELECT * FROM admins WHERE username = %s", [username])

        if result > 0:
            #Get stored hash
            data = cur.fetchone()
            password = data['password']

            #Compare Passwords
            if password_cand == password:
                app.logger.info('PASSWORD MATCH')
                #Passed
                session['admin_logged_in'] = True
                session['username'] = username

                flash("You are now logged in" , 'success')
                return redirect(url_for('sales'))
            else:
                error = 'Invalid login'
                app.logger.info('PASSWORD NOT MATCHED')
                return render_template('admin_login.html', error = error)
            
            #close connection
            cur.close()

        else:
            error = 'Admin Username not found'
            return render_template('admin_login.html', error = error)

    return render_template('admin_login.html') 

#Check if customer logged in
def customer_is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'customer_logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Unauthorized Please login", 'danger')
            return redirect(url_for('login'))
    return wrap

#Check if admin logged in
def admin_is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Unauthorized Please login", 'danger')
            return redirect(url_for('admin_login'))
    return wrap

#Customer Logout
@app.route('/logout')
@customer_is_logged_in
def logout():
    session.clear()
    flash('You are now logged out' , 'success')
    return redirect(url_for('login'))

#Admin Logout
@app.route('/admin_logout')
@admin_is_logged_in
def admin_logout():
    session.clear()
    flash('You are now logged out' , 'success')
    return redirect(url_for('admin_login'))

#Dashboard = Orders page
@app.route('/dashboard')
@customer_is_logged_in
def dashboard():

    #Create Cursor
    cur = mysql.connection.cursor()

    #Get orders
    result = cur.execute("SELECT * FROM sales WHERE customer = %s", [session['username']])

    sales = cur.fetchall()

    if result > 0 :
        return render_template('dashboard.html' , sales = sales)
    else:
        msg = "No orders found"
        return render_template('dashboard.html' , msg =  msg)

    #Close connection
    cur.close()

#Order Form Class
class OrderForm(Form):
    product_type = StringField('Product Type' , [validators.Length(min = 1 , max = 100)])
    manufacturer = StringField('Manufacturer' , [validators.Length(min = 1 , max = 100)])

#Add Order
@app.route('/add_order', methods = ['GET','POST'])
@customer_is_logged_in
def add_order():
    form = OrderForm(request.form)
    if request.method == 'POST' and form.validate():
        product_type = form.product_type.data
        manufacturer = form.manufacturer.data

        #Create Cursor
        cur = mysql.connection.cursor()

        #Find price and quantity of product
        cur.execute('SELECT * FROM products WHERE type = %s AND manufacturer = %s', (product_type, manufacturer))
        data=cur.fetchone()
        price=data['price']
        quantity=data['quantity']          

        #Execute
        cur.execute("INSERT INTO sales(customer, product_type, manufacturer, price) VALUES(%s, %s, %s, %s)", (session['username'], product_type, manufacturer, price))
        
        #also update deliveries table
        cur.execute('INSERT INTO deliveries(customer, product_type, manufacturer) VALUES (%s, %s, %s)', (session['username'], product_type, manufacturer))

        #also update products table
        cur.execute('UPDATE products SET quantity=%s WHERE type=%s AND manufacturer=%s', (quantity-1, product_type, manufacturer))
    
        #Commit to DB
        mysql.connection.commit()

        #Close Connection
        cur.close()
        flash("Order Created", 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_order.html', form = form)  

#Edit Order
@app.route('/edit_order/<string:id>', methods = ['GET','POST'])
@customer_is_logged_in
def edit_order(id):
    #Create Cursor
    cur = mysql.connection.cursor()
    #Get Order by ID
    result = cur.execute("SELECT * FROM sales WHERE id = %s", [id])

    order = cur.fetchone()
    c_user = order['customer']
    p_type = order['product_type']
    manuf = order['manufacturer']

    #select tracking number
    ans=cur.execute('SELECT tracking_no FROM deliveries WHERE customer=%s AND product_type=%s AND manufacturer=%s', (c_user, p_type, manuf))
    data = cur.fetchone()
    tracking_no=data['tracking_no']

    #Find quantity of product
    cur.execute('SELECT quantity FROM products WHERE type = %s AND manufacturer = %s', (p_type, manuf))
    data2=cur.fetchone()
    quantity=data2['quantity'] 

    cur.execute('UPDATE products SET quantity=%s WHERE type=%s AND manufacturer=%s', (quantity+1, p_type, manuf))  

    #Get form
    form = OrderForm(request.form)

    #Populate Order form fields
    form.product_type.data = order['product_type']
    form.manufacturer.data = order['manufacturer']

    if request.method == 'POST' and form.validate():
        product_type = request.form['product_type']
        manufacturer = request.form['manufacturer']

        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute
        cur.execute("UPDATE sales SET product_type = %s, manufacturer = %s WHERE id = %s",(product_type , manufacturer, id))
        result= cur.execute('SELECT price FROM products WHERE type = %s AND manufacturer = %s', (product_type, manufacturer))
        result2= cur.fetchone()
        price=result2['price']

        cur.execute('UPDATE sales SET price = %s WHERE id = %s', (price, id))
        #also edit track_deliveries
        cur.execute('UPDATE deliveries SET product_type = %s, manufacturer = %s WHERE tracking_no = %s', (product_type, manufacturer, tracking_no))
        cur.execute('UPDATE deliveries SET delivery_on = (CURRENT_DATE + INTERVAL FLOOR(RAND() * 4) DAY) WHERE tracking_no = %s', [tracking_no])
        cur.execute('UPDATE deliveries SET received_on = (CURRENT_DATE + INTERVAL FLOOR(RAND() * 4) DAY) WHERE tracking_no = %s', [tracking_no])

        #Find quantity of product
        cur.execute('SELECT quantity FROM products WHERE type = %s AND manufacturer = %s', (product_type, manufacturer))
        data3=cur.fetchone()
        quantity=data3['quantity'] 

        #update products table
        cur.execute('UPDATE products SET quantity=%s WHERE type=%s AND manufacturer=%s', (quantity-1, product_type, manufacturer))

        #Commit to DB
        mysql.connection.commit()

        #Close Connection
        cur.close()
        flash("Order Updated", 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_order.html', form = form)  

#Delete Order
@app.route('/delete_order/<string:id>', methods = ['POST'])
@customer_is_logged_in
def delete_order(id):
    #Create Cursor
    cur = mysql.connection.cursor()

    #find tracking number
    result=cur.execute('SELECT * FROM sales WHERE id=%s', [id])
    order=cur.fetchone()
    result2= cur.execute('SELECT tracking_no FROM deliveries WHERE customer=%s AND product_type=%s AND manufacturer=%s', (order['customer'], order['product_type'], order['manufacturer']))
    data= cur.fetchone()
    tracking_no=data['tracking_no']

    #Find id and quantity of product
    cur.execute('SELECT quantity FROM products WHERE type = %s AND manufacturer = %s', (order['product_type'], order['manufacturer']))
    data2=cur.fetchone()
    quantity=data2['quantity'] 

    #Execute
    cur.execute("DELETE FROM sales WHERE id = %s ", [id])
    #also delete from deliveries
    cur.execute('DELETE FROM deliveries WHERE tracking_no = %s', [tracking_no])
    #also update products
    cur.execute('UPDATE products SET quantity=%s WHERE type=%s AND manufacturer=%s', (quantity+1, order['product_type'], order['manufacturer']))

    #Commit to DB
    mysql.connection.commit()

    #Close Connection
    cur.close()

    flash("Order deleted", 'success')

    return redirect(url_for('dashboard'))

#Track Deliveries
@app.route('/track_deliveries')
@customer_is_logged_in
def track_deliveries():
    #Create Cursor
    cur = mysql.connection.cursor()

    #Get deliveries
    result = cur.execute("SELECT * FROM deliveries WHERE customer=%s", [session['username']])

    deliveries = cur.fetchall()

    if result > 0 :
        return render_template('track_deliveries.html' , deliveries = deliveries)
    else:
        msg = "No deliveries found"
        return render_template('track_deliveries.html', msg =  msg)

    #Close connection
    cur.close()

#Products
@app.route('/products')
@customer_is_logged_in
def products():
    #Create Cursor
    cur = mysql.connection.cursor()

    #Get sales
    result = cur.execute("SELECT * FROM products")

    products = cur.fetchall()

    if result > 0 :
        return render_template('products.html' , products = products)
    else:
        msg = "Sorry, we're out of stock"
        return render_template('products.html', msg =  msg)

    #Close connection
    cur.close()

@app.route('/sales')
@admin_is_logged_in
def sales():
    #Create Cursor
    cur = mysql.connection.cursor()

    #Get sales
    result = cur.execute("SELECT * FROM sales")

    sales = cur.fetchall()

    if result > 0 :
        return render_template('sales.html' , sales = sales)
    else:
        msg = "No sales found"
        return render_template('sales.html', msg =  msg)

    #Close connection
    cur.close()

@app.route('/customer_details')
@admin_is_logged_in
def customer_details():
    #Create Cursor
    cur = mysql.connection.cursor()

    #Get customer details
    result = cur.execute("SELECT * FROM customers")
    customers = cur.fetchall()

    result2 = cur.execute("SELECT * FROM contract")
    contract= cur.fetchall()

    result3 = cur.execute("SELECT * FROM others")
    others= cur.fetchall()

    if result > 0 :
        return render_template('customer_details.html' , customers = customers, contract=contract, others = others)
    else:
        msg = "No customers found"
        return render_template('customers.html', msg =  msg)

    #Close connection
    cur.close()

#Product Form Class
class ProductForm(Form):
    product_type = StringField('Product Type' , [validators.Length(min = 1 , max = 100)])
    manufacturer = StringField('Manufacturer', [validators.Length(min=1, max = 100)])
    price = StringField('Price', [validators.Length(min=1 , max =20)])
    w_id= StringField('Warehouse ID', [validators.Length(min=1 , max =10)])
    quantity= StringField('Quantity', [validators.Length(min=1 , max =20)])
    

#Restock
@app.route('/restock')
@admin_is_logged_in
def restock():

    #Create Cursor
    cur = mysql.connection.cursor()

    #Get articles
    result = cur.execute("SELECT * FROM products")

    products = cur.fetchall()

    if result > 0 :
        return render_template('restock.html' , products = products)
    else:
        msg = "No products found"
        return render_template('restock.html', msg =  msg)

    #Close connection
    cur.close()

#Add product
@app.route('/add_product', methods = ['GET','POST'])
@admin_is_logged_in
def add_product():
    form = ProductForm(request.form)
    if request.method == 'POST' and form.validate():
        product_type = form.product_type.data
        manufacturer = form.manufacturer.data
        price = form.price.data
        w_id = int(form.w_id.data)
        quantity=int(form.quantity.data)

        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute
        cur.execute("INSERT INTO products(type, manufacturer, price, w_id, quantity) VALUES(%s, %s, %s, %s, %s)", (product_type, manufacturer, price, w_id, quantity))
    
        #Commit to DB
        mysql.connection.commit()

        #Close Connection
        cur.close()
        flash("Product Added", 'success')

        return redirect(url_for('restock'))

    return render_template('add_product.html', form = form)   

#Delete product
@app.route('/delete_product/<string:id>', methods = ['POST'])
@admin_is_logged_in
def delete_product(id):
    #Create Cursor
    cur = mysql.connection.cursor()

    #Execute
    cur.execute("DELETE FROM products WHERE id = %s ", [id])

    #Commit to DB
    mysql.connection.commit()

    #Close Connection
    cur.close()

    flash("Product deleted", 'success')

    return redirect(url_for('restock'))

#Phone Order Form Class
class PhoneOrderForm(Form):
    customer_username = StringField('Customer Username' , [validators.Length(min = 1 , max = 30)])
    product_type = StringField('Product Type' , [validators.Length(min = 1 , max = 100)])
    manufacturer = StringField('Manufacturer', [validators.Length(min=1, max = 100)])

#Phone Orders
@app.route('/phone_orders')
@admin_is_logged_in
def phone_orders():

    #Create Cursor
    cur = mysql.connection.cursor()

    #Get articles
    result = cur.execute("SELECT * FROM sales")

    sales = cur.fetchall()

    if result > 0 :
        return render_template('phone_orders.html' , sales = sales)
    else:
        msg = "No orders found"
        return render_template('phone_orders.html', msg =  msg)

    #Close connection
    cur.close()

#Add phone order
@app.route('/add_phone_order', methods = ['GET','POST'])
@admin_is_logged_in
def add_phone_order():
    form = PhoneOrderForm(request.form)
    if request.method == 'POST' and form.validate():
        customer_username= form.customer_username.data
        product_type = form.product_type.data
        manufacturer = form.manufacturer.data

        #Create Cursor
        cur = mysql.connection.cursor()

        #Find price of product
        cur.execute('SELECT * FROM products WHERE type = %s AND manufacturer = %s', (product_type, manufacturer))
        data=cur.fetchone()
        price=data['price']
        quantity=data['quantity']

        #Execute
        cur.execute("INSERT INTO sales(customer, product_type, manufacturer, price) VALUES(%s, %s, %s, %s)", (customer_username, product_type, manufacturer, price))

        #also update deliveries table
        cur.execute('INSERT INTO deliveries(customer, product_type, manufacturer) VALUES (%s, %s, %s)', (customer_username, product_type, manufacturer))

        #also update products
        cur.execute('UPDATE products SET quantity=%s WHERE type=%s AND manufacturer=%s', (quantity-1, product_type, manufacturer))

        #Commit to DB
        mysql.connection.commit()

        #Close Connection
        cur.close()
        flash("Phone Order Added", 'success')

        return redirect(url_for('phone_orders'))

    return render_template('add_phone_order.html', form = form)   

#Delete phone order
@app.route('/delete_phone_order/<string:id>', methods = ['POST'])
@admin_is_logged_in
def delete_phone_order(id):
    #Create Cursor
    cur = mysql.connection.cursor()

    #find tracking number
    result=cur.execute('SELECT * FROM sales WHERE id=%s', [id])
    order=cur.fetchone()
    result2= cur.execute('SELECT tracking_no FROM deliveries WHERE customer=%s AND product_type=%s AND manufacturer=%s', (order['customer'], order['product_type'], order['manufacturer']))
    data= cur.fetchone()
    tracking_no=data['tracking_no']

    #find product quantity
    cur.execute('SELECT quantity FROM products WHERE type=%s AND manufacturer=%s', (order['product_type'], order['manufacturer']))
    data2=cur.fetchone()
    quantity=data2['quantity']

    #Execute
    cur.execute("DELETE FROM sales WHERE id = %s ", [id])
    #also delete from deliveries
    cur.execute('DELETE FROM deliveries WHERE tracking_no = %s', [tracking_no])
    #also update products
    cur.execute('UPDATE products SET quantity=%s WHERE type=%s AND manufacturer=%s', (quantity+1, order['product_type'], order['manufacturer']))

    #Commit to DB
    mysql.connection.commit()

    #Close Connection
    cur.close()

    flash("Order deleted", 'success')

    return redirect(url_for('phone_orders'))

#Warehouse Form Class
class WarehouseForm(Form):
    region = StringField('Region', [validators.Length(min=1, max = 100)])

#Warehouses
@app.route('/warehouses')
@admin_is_logged_in
def warehouses():

    #Create Cursor
    cur = mysql.connection.cursor()

    #Get articles
    result = cur.execute("SELECT * FROM warehouses")

    warehouses = cur.fetchall()

    if result > 0 :
        return render_template('warehouses.html' , warehouses = warehouses)
    else:
        msg = "No warehouses found"
        return render_template('warehouses.html', msg =  msg)

    #Close connection
    cur.close()

#Add warehouse
@app.route('/add_warehouse', methods = ['GET','POST'])
@admin_is_logged_in
def add_warehouses():
    form = WarehouseForm(request.form)
    if request.method == 'POST' and form.validate():
        region = form.region.data

        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute
        cur.execute("INSERT INTO warehouses(region) VALUES(%s)", [region])
    
        #Commit to DB
        mysql.connection.commit()

        #Close Connection
        cur.close()
        flash("Warehouse Added", 'success')

        return redirect(url_for('warehouses'))

    return render_template('add_warehouses.html', form = form)   

#Delete warehouse
@app.route('/delete_warehouse/<string:id>', methods = ['POST'])
@admin_is_logged_in
def delete_warehouse(id):
    #Create Cursor
    cur = mysql.connection.cursor()

    #Execute
    cur.execute("DELETE FROM warehouses WHERE w_id = %s ", [id])

    #Commit to DB
    mysql.connection.commit()

    #Close Connection
    cur.close()

    flash("Warehouse deleted", 'success')

    return redirect(url_for('warehouses'))

if __name__ =='__main__':
    app.secret_key='noam'
    app.run(debug=True)
