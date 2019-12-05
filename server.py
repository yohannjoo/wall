from flask import Flask, render_template, redirect, request, session, flash, jsonify
import re
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
from time import strftime, localtime

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "buildthatwall"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z]+$')

@app.route('/') #gives us the root page
def home():
    if 'id' not in session:
        session['id'] = 0
    if 'first_name' not in session:
        session['first_name'] = None
    if 'login_status' not in session:
        session['login_status'] = False
    if 'sent_msg_cnt' not in session:
        session['sent_msg_cnt'] = 0
    return render_template('logreg.html')

@app.route('/register', methods=['POST'])
def validate():
    error = False
    mysql = connectToMySQL('TheWall')
    query = "SELECT * FROM users WHERE email = %(em)s "
    data = {
        'em':request.form['email']
    }
    check = mysql.query_db(query, data)

    if len(request.form["first_name"]) == 0 or len(request.form["last_name"]) == 0 or len(request.form["email"]) == 0 or len(request.form["password"]) == 0 or len(request.form["confirm_password"]) == 0:
        flash("All input fileds are required", 'top')
        error = True
    else:
        if len(request.form['first_name'])<2:
            flash('first name must be at least 2 characters', 'first_name')
            error = True
        if len(request.form['last_name']) < 2:
            flash('Last name must be at least 2 characters', 'last_name')
            error = True
        # if check: 
        #     if check[0]['email'] == request.form['email']:
        #         flash('Email has already been registered', 'email')
        #         error = True
        if not EMAIL_REGEX.match(request.form['email']):
            flash('Invalid Email format', 'email')
            error = True
        if len(request.form['password']) < 8:
            flash('Password must be longer than 8 characters!', 'password')
            error = True
        if request.form['password'] != request.form['confirm_password']:
            flash("Passwords do not match", 'password')
            error = True
    
    if error == True:
        return redirect('/')
    elif error == False:
        reg_pass_hash = bcrypt.generate_password_hash(request.form['password'])
        mysql = connectToMySQL('TheWall')
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s, NOW(), NOW());"
        data = {
            'fn': request.form['first_name'],
            'ln': request.form['last_name'],
            'em': request.form['email'],
            'pw': reg_pass_hash
        }
        mysql.query_db(query, data)
        flash('Registration Successful. Please Log In')
        return redirect('/')

@app.route('/login', methods=["POST"])
def login():
    mysql = connectToMySQL('TheWall')
    query = "SELECT * FROM users WHERE email = %(em)s"
    data = {
        'em': request.form['email']
    }
    check = mysql.query_db(query, data)

    if check:
        if check[0]['email'] == request.form['email']:
            if bcrypt.check_password_hash(check[0]['password'], request.form['password']):
                session['login_status'] = True
                session['first_name'] = check[0]['first_name']
                session['id'] = check[0]['id']
                return redirect('/home')
            else:
                flash('Invalid Credentials: Login Denied!', 'login_top')
                return redirect('/')
    else:
        flash('Invalid Credentials: Login Denied!', 'login_top')
        return redirect('/')

@app.route('/home')
def home_index():
    if session['login_status'] == True:
        time = strftime('%Y-%m-%d %H:%M:%S', localtime())
        mysql = connectToMySQL('TheWall')
        query = "SELECT messages.id, messages.user_id, messages.sent_to_id, messages.message, messages.created_at, messages.updated_at, users.first_name, users.last_name FROM messages join users ON users.id = messages.user_id WHERE messages.sent_to_id = %(uid)s ORDER BY messages.created_at DESC;"
        data = {
            'uid':session['id']
        }
        message_check = mysql.query_db(query, data)
        count = 0
        for i in message_check:
            count += 1
        
        mysql2 = connectToMySQL('TheWall')
        send_query = "SELECT * FROM users WHERE NOT id = %(uid)s;"
        send_data = {
            'uid':session['id']
        }
        send_check = mysql2.query_db(send_query, send_data)
        return render_template('wall.html', messages = message_check, time=time, count=count, sends=send_check)
    else:
        return redirect('/home')

@app.route('/send_messages', methods=["POST"])
def send_msg():
    mysql = connectToMySQL('TheWall')
    query = "SELECT * FROM users WHERE id = %(id)s"
    data = {
        'id':request.form['button']
    }
    users = mysql.query_db(query, data)

    if len(request.form['message'])>250:
        flash("Message cannot be longer than 250 characters!", "send_error")
        return redirect('/home')
    if len(request.form['message']) < 8:
        flash("Message must be at least 8 characters!", 'send_error')
        return redirect('/home')
    else:
        mysql = connectToMySQL('TheWall')
        query = "INSERT INTO messages (user_id, sent_to_id, message, created_at, updated_at) VALUES (%(uid)s, %(sid)s, %(me)s, NOW(), NOW());"
        data = {
            'uid':session['id'],
            'sid':request.form['button'],
            'ms':request.form['message']
        }
        mysql.query_db(query, data)
        session['send_msg_cnt'] += 1
        return redirect('/home')

@app.route('/delete_message/<message_id>')
def del_message(message_id):
    mysql = connectToMySQL('TheWall')
    query = 'SELECT * FROM messages WHERE id = %(mid)s;'
    data = {
        'mid':message_id
    }
    check = mysql.query_db(query, data)
    if check[0]['send_to_id'] != session['id']:
        return redirect('/danger')
    elif check[0]['sent_to_id'] == session['id']:
        mysql = connectToMySQL("TheWall")
        query = "DELETE FROM messages WHERE id = %(ms)s"
        data = {
            'ms':message_id
        }
        mysql.query_db(query, data)
        return redirect('/home')

@app.route('/danger')
def danger():
    session['login_status'] = False
    return render_template('danger.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ =="__main__":
    app.run(debug=True)
