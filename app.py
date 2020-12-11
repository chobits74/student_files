from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy 
from flask_admin import Admin 
from flask_login import UserMixin, LoginManager, login_user,login_required, logout_user
from flask_admin.contrib.sqla import ModelView
from flask_user import current_user, roles_required, UserManager
from datetime import datetime
from flask_admin import BaseView, expose
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['FLASK_ADMIN_SWATCH'] = 'United'
app.config['SECRET_KEY'] = "secret Admirer"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///student_file.sqlite'

#db = SQLAlchemy(app)

login = LoginManager(app)
db = SQLAlchemy(app)

@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


    # Initialize Flask-SQLAlchemy
#db = SQLAlchemy(app)
    

    # Define the User data-model.
    # NB: Make sure to add flask_user UserMixin !!!
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')

        # User authentication information. The collation='NOCASE' is required
        # to search case insensitively when USER_IFIND_MODE is 'nocase_collation'.
    email = db.Column(db.String(255, collation='NOCASE'), nullable=False, unique=True)
        
    password = db.Column(db.String(255), nullable=False, server_default='')

        # User information
    first_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
    last_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
    reg_number = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        
        # Define the relationship to Role via UserRoles
    roles = db.relationship('Role', secondary='user_roles')

    def __init__(self, email, password, first_name, last_name, reg_number):
        self.email = email
        self.password = password
        self.first_name = first_name
        self.last_name = last_name
        self.reg_number = reg_number

    def __repr__(self):
        return self.first_name

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Define the Role data-model
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)

    # Define the UserRoles association table
class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

class FileStorage(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer(), primary_key=True)
    type = db.Column(db.String(10))
    data = db.Column(db.LargeBinary())
    semester = db.Column(db.String(10))
    Year = db.Column(db.Integer())
    run_num = db.Column(db.Integer())
    date_created = db.Column(db.Date, default=datetime.now)

        # Define the relationship to User via UserFiles
    stores = db.relationship('User', secondary = 'user_files')

    #contruct filestorage model
    def __repr__(self):
        return self.type

class UserFiles(db.Model):
    __tablename__ = 'user_files'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    file_id = db.Column(db.Integer(), db.ForeignKey('files.id', ondelete='CASCADE'))
    

    # Setup Flask-User and specify the User data-model

#user_manager = UserManager(app, db, User)

class UserView(ModelView):
    column_exclude_list = []
    column_display_pk = True
    can_create = True
    can_edit = True
    can_delete = True
    can_export = True

    def on_model_change(self, form, model, is_created):
        model.password = generate_password_hash(model.password, method='sha256')

    def is_accessible(self):
        return  not current_user.is_authenticated

class MyFileView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

@app.route('/')
def index():
    return render_template('login.html')
    #return '<a href="/admin/">Click me to Admin page</a>'

#class HomeView(BaseView):
#   @expose('/')
#  def index(self):
# #     return self.render(home_index.html)
@app.route('/login')
def login():
    return render_template('login.html')
    
@app.route('/login', methods = ['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    checkme = True if request.form.get('checkme') else False

    user = User.query.filter_by(email = email).first()
    login_user(user)

    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login'))

    #login_user(user, checkme=checkme)
    return redirect(url_for('folio'))

@app.route('/folio')
@login_required
def folio():
    return render_template('folio.html',first_name = current_user.first_name )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
    
    
admin = Admin(app, 'genki?', base_template='layout.html', template_mode='bootstrap3')
admin.add_view(UserView(User, db.session))
admin.add_view(MyFileView(FileStorage, db.session))

    # Create all database tables
#db.create_all()



if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)