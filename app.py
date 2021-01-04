from flask import Flask, render_template, url_for, flash, redirect
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError, IntegerField, RadioField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = '792322cf65e1fabb70b75e0b926750b4158940f43bcde2f3a93ab717aec5df8324b11ec53b123164cb51669b51004b3af73899b32c75d8679e0b518d68192aa1'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id          = db.Column(db.Integer, primary_key=True)
    first_name  = db.Column(db.String(30), nullable=True)
    last_name   = db.Column(db.String(30), nullable=True)
    gender      = db.Column(db.String(5), nullable=True)
    grade       = db.Column(db.Integer, nullable=False)
    username    = db.Column(db.String(30), unique=True, nullable=False)
    email       = db.Column(db.String(120), unique=True, nullable=False)
    password    = db.Column(db.String(60), unique=True, nullable=False)

    def __repr__(self):
        return f"{username}(id='{id}', email='{email}')"

class SignUpForm(FlaskForm):
    first_name          = StringField("First name: ", validators=[DataRequired()])
    last_name           = StringField("Last name: ", validators=[DataRequired()])
    grade               = IntegerField("Grade: ", validators=[DataRequired()])
    gender              = RadioField("Gender: ", validators=[DataRequired()], choices=['Male', 'Female'])
    username            = StringField("Username: ", validators=[DataRequired(), Length(min=3, max=30)])
    email               = StringField("Email: ", validators=[DataRequired(), Email()])
    password            = PasswordField("Password: ", validators=[DataRequired()])
    confirm_password    = PasswordField("Confirm Password: ", validators=[DataRequired(), EqualTo('password')])
    submit              = SubmitField('Sign Up')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('There is already an account with that email. Try logging in instead.')

class LoginForm(FlaskForm):
    email = StringField("Email: ", validators=[DataRequired(), Email()])
    password = PasswordField("Password: ", validators=[DataRequired()])
    remember = BooleanField('Remember Me: ')
    submit = SubmitField('Login')

@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html', showNav=True, User=User(), title='GTG - Home')

@app.route('/sign-up', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = SignUpForm()
    if form.validate_on_submit():
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, grade=form.grade.data,  gender=form.gender.data, username=form.username.data, email=form.email.data, password=password, )
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, showNav=True, title='GTG - Sign Up')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Either the email or password is wrong.')
    return render_template('login.html', form=form, showNav=True, title='GTG - Login')

@app.route('/account')
def account():
    return '<h1>In Development</h1>'

@app.route('/gpa')
def calculator():
    return render_template('calculator.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)