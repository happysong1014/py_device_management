from flask import Flask, render_template, request, redirect, url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'your-secret-key'  # replace 'your-secret-key' with your real secret key
db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))  # add this new field
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(100))
    address = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Admin(UserMixin):
    id = 1
    email = 'admin@gznaao.com'
    is_admin = True


with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    if int(user_id) == 1:
        return Admin()
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('user_devices'))

    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        admin_id = request.form.get('admin_id')
        password = request.form.get('password')
        if admin_id != 'Admin' or password != '123456':
            error = 'Invalid Credentials. Please try again.'
        else:
            login_user(Admin())
            return redirect(url_for('admin'))
    return render_template('admin_login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    users = User.query.all()
    devices = Device.query.all()

    return render_template('admin.html', users=users, devices=devices)


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    if request.method == 'POST':
        id = request.form.get('id')
        name = request.form.get('name')  # get the name from the form
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if the user with the given ID already exists.
        user = User.query.filter_by(id=id).first()
        if user:
            flash('The ID is already in use. Please choose a different one.', 'error')
            return render_template('create_user.html')

        # Check if the email already exists.
        user = User.query.filter_by(email=email).first()
        if user:
            flash('The email is already in use. Please choose a different one.', 'error')
            return render_template('create_user.html')

        user = User(id=id, name=name, email=email)  # add the name to the new user
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('admin'))

    return render_template('create_user.html')


    return render_template('create_user.html')




@app.route('/create_device', methods=['GET', 'POST'])
@login_required
def create_device():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    users = User.query.all()  # 查询所有用户

    if request.method == 'POST':
        type = request.form.get('type')
        address = request.form.get('address')
        user_id = request.form.get('user_id')
        device = Device(type=type, address=address, user_id=user_id)
        db.session.add(device)
        db.session.commit()

        return redirect(url_for('admin'))

    return render_template('create_device.html', users=users)  # 将用户传递给模板


@app.route('/user_devices')
@login_required
def user_devices():
    devices = Device.query.filter_by(user_id=current_user.id)
    return render_template('user_devices.html', devices=devices)

if __name__ == '__main__':
    app.run(debug=True)
