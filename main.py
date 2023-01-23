from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from os import path
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user, LoginManager


db = SQLAlchemy()
DB_NAME = 'database.db'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'whatever'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
db.init_app(app)


############################ USER | Database table ##########################################
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))


########################### Create DB ########################################################
with app.app_context():
    db.create_all()

###########################
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


####################### Home | Index ###########################################################
@app.route('/')
@app.route('/home')
@login_required
def home():
    return render_template('home.html', user=current_user)


####################### SignUp #############################################################
@app.route('/signUp', methods=['GET', 'POST'])
def signUp():

    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', category='error')
        else:
            if len(email) < 4:
                flash('Email must have more than 3 characters.', category='error')
            elif len(name) < 2:
                flash('Name must have more than 1 character.', category='error')
            elif password1 != password2:
                flash('Passwords must be the same.', category='error')
            elif len(password1) < 4:
                flash('Password must have at least 4 characters.', category='error')
            else:
                new_user = User(email=email, name=name, password=generate_password_hash(password1, method='sha256'))
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('home'))

    return render_template('signUp.html', user=current_user)


####################### Login #########################################################################
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in seccesfully', category='success')
                login_user(user, remember=True)
                return redirect(url_for('home'))
            else:
                flash('Incorrect password', category='error')
        else:
            flash('User does not exist', category='error')
    return render_template('login.html', user=current_user)

####################### Logout #####################################################################
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)