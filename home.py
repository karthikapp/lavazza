from flask import Flask
from flask import render_template,redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user,login_required, logout_user, current_user
import os
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash


APP_ROOT = os.path.dirname(os.path.abspath(__file__))   # refers to application_top
APP_STATIC = os.path.join(APP_ROOT, 'database')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////' + APP_STATIC + '/login.db'
app.config['SECRET_KEY'] = 'spectrum7tech99'

Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50), unique=False)
    lastname = db.Column(db.String(50), unique=False)
    title = db.Column(db.String(50), unique=False)
    password = db.Column(db.String(80), unique=False)
    email = db.Column(db.String(50), unique=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Please enter a valid Email ID'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember Me')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Please enter a valid Email ID'), Length(max=50)])
    Firstname = StringField('First Name', validators=[InputRequired(), Length(max=50)])
    Lastname = StringField('Last Name', validators=[InputRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    title = SelectField(u'Title', choices=[('hop', 'Head of Operations'), ('hof', 'Head of Finance'), ('finman', 'Manager, Finance')])
  



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
    	user = User.query.filter_by(email = form.email.data).first()
    	if user:
    		if check_password_hash(user.password,form.password.data):
    			login_user(user, remember = form.remember.data)
    			return redirect(url_for('dashboard'))
    	return '<h1> Invalid Username or Password </h1>'
    	
       

        return '<h1>Invalid Email or Password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form = form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    registerform = RegisterForm()

    if registerform.validate_on_submit():
    	hashed_password = generate_password_hash(registerform.password.data, method='sha256')
    	new_user = User(firstname = registerform.Firstname.data, lastname = registerform.Lastname.data, email = registerform.email.data, title = registerform.title.data, password = hashed_password)
    	db.session.add(new_user)
    	db.session.commit()
    	return '<h1> new user created <h1>'
       

     #    return '<h1>Invalid Email or Password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('register.html', registerform = registerform)

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html',name=current_user.firstname)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()