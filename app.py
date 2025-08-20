from flask import Flask, render_template, request
import sqlite3
import bcrypt
import requests


app = Flask(__name__)



def create_table():
    conn = sqlite3.connect('register.db')
    cursor = conn.cursor()

    cursor.execute('''
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                passw TEXT,
                number_phone VARCHAR
            )
        ''')

    conn.commit()
    conn.close()


def create_password_hash(passw):
    salt = bcrypt.gensalt()
    hash_passw = bcrypt.hashpw(passw.encode('utf-8'), salt)
    return hash_passw.decode('utf-8')


def register_user(name, passw, number_phone):
    conn = sqlite3.connect('register.db')
    cursor = conn.cursor()

    hash_passw = create_password_hash(passw)

    cursor.execute('INSERT INTO user (name, passw, number_phone) VALUES (?, ?, ?)', (name, hash_passw, number_phone))

    conn.commit()
    conn.close()


def verify_hash_passw(passw, hash_passw):
    return bcrypt.checkpw(passw.encode('utf-8'), hash_passw.encode('utf-8'))


def verify_user(name, passw):
    conn = sqlite3.connect('register.db')
    cursor = conn.cursor()

    cursor.execute('SELECT passw FROM user WHERE name = ?', (name,))
    user = cursor.fetchone()

    conn.close()

    if user is not None:
        hash_passw = user[0]
        if verify_hash_passw(passw, hash_passw):
            return True 
    
    return False 




@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    passw = request.form['passw']
    number_phone = request.form.get("number_phone", None)

    if name == '' or passw == '' or number_phone == "":
        return 'Please fill in all fields.'

    create_table()
    register_user(name, passw, number_phone)

    return render_template('index.html', message1='User registered successfully.')


@app.route('/verify', methods=['POST'])
def verify():
    name = request.form['name']
    passw = request.form['passw']

    print(f'Name received: {name}')  
    print(f'Password received: {passw}')  

    if name == '' or passw == '':
        return 'Fill in all fields' 

    if verify_user(name, passw):
        print('Valid user.') 
        return render_template('index.html', message2='Valid user.')
    else:
        print('Not found.')  
        return render_template('index.html', message2='Invalid user.')




if __name__ == '__main__':
    app.run(debug=True)
