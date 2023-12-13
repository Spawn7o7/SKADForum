#to fully initialize the app use the following commands in the terminal

# to install all packages at once use full pip install command line below
# pip install flask flask_sqlalchemy SQLALchemy flask-cors flask_login flask_bcrypt flask_wtf wtforms email_validator flask-admin passlib

# if you are getting errors when trying to run install the bellow versions I think it depends on python version
# pip install flask flask_sqlalchemy SQLALchemy flask-cors flask-login flask-bcrypt flask-wtf wtforms email-validator flask-admin passlib

# IMPORTANT NOTICE!!!!
# flask_login or some pip installed versions can give erors when running
# the workaround to fix is either do

# pip uninstall werkzeug
# pip install werkzeug==2.3.0

# OR (I didn't try this one)(also not sure for other pip installs)

# pip install git+https://github.com/maxcountryman/flask-login.git

 #comments in all caps are for the lines that will allow you to create an admin account, two lines in app.py, one line in register.html


from flask import Flask, render_template, url_for, redirect, request, flash, abort, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
from passlib.hash import sha256_crypt
from datetime import datetime
#from flask_admin.form.widgets import Select2Widget

app = Flask(__name__)
CORS(app)
admin = Admin(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///databaseInfo.db' # <---you can change this to a different URI (might need to create more)
db = SQLAlchemy(app)  # db is initialized after creating the app
migrate = Migrate(app, db)
app.config['SECRET_KEY'] = 'fortnitebattlepass'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

############# Models ######################

# database model for the login
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True) 
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    admins = db.Column(db.Boolean, default=False) #boolean for permissions, "true" or "1" if admin, "false" or "0" if not, will remove from choice just has to exist in db
    #Establish one-to-many relationship with Post
    posts = db.relationship('Post', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(250), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    view_count = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    def increment_view_count(self):
        if self.view_count is None:
            self.view_count = 0
        else:
            self.view_count += 1
        db.session.commit()

    @property
    def reply_count(self):
        return self.comments.count()

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='comments')


# used for registration 
class Registration(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "username"})
    firstname = StringField(validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "enter your first name"})
    lastname = StringField(validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "enter your last name"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "password"})
    #admins = BooleanField('Are You a Admin?') #UNCOMMMENT THIS PART TO CREATE AN ADMIN ACCOUNT
    submit = SubmitField("Register")
    
    def validate_username(self, username):
        existing_username = User.query.filter_by(username=username.data).first()
        if existing_username:
            raise ValidationError("This Username is taken")


# used for logging in
class LoggingIn(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "password"})
    submit = SubmitField("Log In")


############# ModelView ################

class UserAdminView(ModelView):
    column_list = ('id', 'username', 'firstname', 'lastname', 'password', 'admins')
    can_create = True
    can_edit = True
    can_delete = True
    column_searchable_list = ['id','username', 'firstname', 'lastname']
    column_filters = ['admins']


admin.add_view(UserAdminView(User, db.session))


class PostAdminView(ModelView):
    column_list = ('id', 'title', 'content', 'topic', 'timestamp','increment_view_count', 'user_id')
    can_create = True
    can_edit = True
    can_delete = True
    column_searchable_list = ['id', 'title', 'content', 'topic']
    column_filters = ['timestamp', 'user_id']
admin.add_view(PostAdminView(Post, db.session))

class CommentAdminView(ModelView):
    column_list = ('id', 'content', 'timestamp', 'post_id', 'user_id')
    can_create = True
    can_edit = True
    can_delete = True
    column_searchable_list = ['id', 'content']
    column_filters = ['timestamp', 'post_id', 'user_id']
admin.add_view(CommentAdminView(Comment, db.session))


class LogoutView(BaseView):
    @expose('/')
    def index(self):
        logout_user()
        return redirect(url_for('login'))

admin.add_view(LogoutView(name='Logout', endpoint='logout'))

# Initialize the database
with app.app_context():
    db.create_all()


@app.before_request
def check_for_admin(*args, **kw):
    if request.path.startswith('/admin'):
        if not current_user.admins:
            return redirect(url_for('home'))

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = Registration()
    if form.validate_on_submit():
        hashed_password = sha256_crypt.hash(form.password.data)
        new_user = User(username=form.username.data, 
                        firstname=form.firstname.data,
                        #admins=int(form.admins.data), #UNCOMMMENT THIS PART TO CREATE AN ADMIN ACCOUNT
                        lastname=form.lastname.data, password=hashed_password
                        ) 
        db.session.add(new_user)
        db.session.flush() 
        
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html", form = form)


#MODIFIED 
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoggingIn()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and sha256_crypt.verify(form.password.data, user.password):
            login_user(user) 
            if user.admins:
                return redirect(url_for('admin_page')) 
            else:     
                return redirect(url_for('home'))
    return render_template("login.html", form=form)


@app.route('/home')
@login_required 
def home():
    posts = Post.query.all()
    
    # Get the count of posts for each topic
    post_counts = db.session.query(Post.topic, func.count(Post.id)).group_by(Post.topic).all()
    topic_counts = dict(post_counts)    # store topic counts
    unique_posts = []                   # list to store unique posts

    for post in posts:
        post.topic_count = topic_counts.get(post.topic, 0)
        unique_posts.append(post)

    seen_topics = set()
    unique_posts = []
    for post in posts:
        if post.topic not in seen_topics:
            seen_topics.add(post.topic)
            unique_posts.append(post)
            
    return render_template("home.html", posts=unique_posts)

@app.route('/home_sort', methods=['GET'])
@login_required
def home_sort():
    sorting_criterion = request.args.get('sorting_criterion', 'everything')

    # Get the count of posts for each topic
    post_counts = db.session.query(Post.topic, func.count(Post.id)).group_by(Post.topic).all()
    topic_counts = dict(post_counts)  # store topic counts

    # Retrieve posts
    posts = Post.query.all()

    # Update the topic count for each post
    for post in posts:
        post.topic_count = topic_counts.get(post.topic, 0)

    if sorting_criterion == 'alphabetical':
        posts = sorted(posts, key=lambda x: x.topic)
    elif sorting_criterion == 'total_posts':
        posts = sorted(posts, key=lambda x: x.topic_count, reverse=True)
    elif sorting_criterion == 'date_posted':
        posts = sorted(posts, key=lambda x: x.timestamp, reverse=True)

    seen_topics = set()
    unique_posts = []
    for post in posts:
        if post.topic not in seen_topics:
            seen_topics.add(post.topic)
            unique_posts.append(post)

    return render_template("home.html", posts=unique_posts, sorting_criterion=sorting_criterion)


####################################################----Bugged Comments----###################################################

# This thing does work to create an api that stores the comments
@app.route('/api/comments/<int:post_id>')
def api_get_comments(post_id):
    comments = Comment.query.filter_by(post_id=post_id).all()

    # Convert comments to a list of dictionaries
    comments_data = []
    for comment in comments:
        comments_data.append({
            'id': comment.id,
            'content': comment.content,
            'timestamp': comment.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'user': {
                'id': comment.user.id,
                'username': comment.user.username,
            }
        })

    return jsonify(comments_data)


########## This works for adding comments! actually calling the comments doesn't work

@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    comment_content = request.form.get('comment_content')
    parent_comment_id = request.form.get('parent_comment_id')

    new_comment = Comment(content=comment_content, post_id=post_id, user_id=current_user.id)

    if parent_comment_id:
        # This is a reply to a comment
        parent_comment = Comment.query.get_or_404(parent_comment_id)
        new_comment.parent_comment = parent_comment

    db.session.add(new_comment)
    db.session.commit()

    return redirect(url_for('postdetails', post_id=post_id))

####################################################----END----###################################################

@app.route('/postdetails/<int:post_id>')
@login_required
def postdetails(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()
    post.increment_view_count()

    return render_template("postdetails.html", post=post, comments=comments)

@app.route('/profile')
@login_required 
def profile():
        
    return render_template("profile.html")


##################### Insert postdetails/<url> here?? #######################333

@app.route('/posts/<topic_name>')
@login_required 
def topic_details(topic_name):
        
    posts = Post.query.filter_by(topic=topic_name).all()

    return render_template("posts.html", posts=posts, topic_name=topic_name, Comment=Comment)

@app.route('/posts_sort/<topic_name>')
@login_required 
def posts_sort(topic_name):
    sorting_criterion = request.args.get('sorting_criterion', 'everything')
    
    posts = Post.query.filter_by(topic=topic_name).all()

    if sorting_criterion == 'alphabetical':
        posts = sorted(posts, key=lambda x: x.title)
    elif sorting_criterion == 'views':
        posts = sorted(posts, key=lambda x: x.view_count, reverse=True)
    elif sorting_criterion == 'date_posted':
        posts = sorted(posts, key=lambda x: x.timestamp, reverse=True)

    return render_template("posts.html", posts=posts, topic_name=topic_name, sorting_criterion=sorting_criterion, Comment=Comment)

#############################################################################

@app.route('/createpost', methods=['GET', 'POST'])
@login_required  
def createpost():
    #Get input data from form
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        topic = request.form['topic']
        newPost = Post(title=title, content=content, topic=topic, user_id=current_user.id)

        # Update db w newPost
        db.session.add(newPost)
        db.session.commit()

        # Return to forum home page (Can change later)
        return redirect(url_for('home'))
    
    return render_template("createpost.html")


#Route for searching
@app.route('/search', methods=['GET'])
def search_results():
    search_query = request.args.get('search_query')
    topic_filter = request.args.get('topic')  # Get topic
    if topic_filter:
        results = Post.query.filter(Post.title.contains(search_query), Post.topic == topic_filter).all()
    else:
        results = Post.query.filter(Post.title.contains(search_query)).all()
    topics = set([post.topic for post in Post.query.all()]) 
    return render_template('search_results.html', results=results, topics=topics, current_topic=topic_filter)


@app.route('/admin/')
@login_required
def admin_page():
    if current_user.admins:
        return render_template('admin.html')
    else:
        abort(403)  # Forbidden error if the user is not an admin
        

# for logging out
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



if __name__ == "__main__":
    app.run()
