from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime 
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, TextAreaField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class ReviewForm(FlaskForm):
    book_name = StringField('Book Name', validators=[DataRequired()])
    author_name = StringField('Author Name', validators=[DataRequired()])
    rating = IntegerField('Rating', validators=[DataRequired()])
    review_text = TextAreaField('Review', validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class BookReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_name = db.Column(db.String(255), nullable=False)
    author_name = db.Column(db.String(255), nullable=False)
    rating = db.Column(db.Integer)
    review_text = db.Column(db.Text)
    review_date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('book_reviews', lazy=True))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        print(f"Entered Username: {username}")
        print(f"Entered Password (Hashed): {bcrypt.generate_password_hash(password).decode('utf-8')}")

        user = User.query.filter_by(username=username).first()

        if user:
            print(f"User Password Hash: {user.password_hash}")
            if user.check_password(password):
                login_user(user)
                flash('Logged in successfully!', 'success')
                print("Redirecting to dashboard")
                return redirect(url_for('dashboard'))
            else:
                flash('Login failed. Password is incorrect.', 'danger')
        else:
            flash('Login failed. User not found.', 'danger')

    print("Form validation failed. Errors:", form.errors)
    return render_template('login.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            new_user = User(username=username)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()

            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    print("Current User:", current_user) 
    user_reviews = BookReview.query.filter_by(user=current_user).all()
    return render_template('dashboard.html', user_reviews=user_reviews)

@app.route('/post_review', methods=['GET', 'POST'])
@login_required
def post_review():
    form = ReviewForm()

    if form.validate_on_submit():
        new_review = BookReview(
            user_id=current_user.id,
            book_name=form.book_name.data,
            author_name=form.author_name.data,
            rating=form.rating.data,
            review_text=form.review_text.data
        )

        db.session.add(new_review)
        db.session.commit()

        flash('Review added successfully!', 'success')
        print("Redirecting to dashboard")
        return redirect(url_for('dashboard'))

    return render_template('post_review.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    print("Redirecting to index")
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
