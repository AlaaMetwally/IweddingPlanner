import os
from flask import Flask, render_template, request, redirect, url_for
from flask import jsonify, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
from flask_login import login_required, current_user, login_user
from auth import auth as auth_blueprint
from auth import app, db
from flask_oauth import OAuth
from models import User, Category, Item
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
# configuring the application

FACEBOOK_APP_ID = '2200829739985090'
FACEBOOK_APP_SECRET = 'e1cc58ec611cd31543c0646b2d7ee70d'
AUTH_URL = 'https://www.facebook.com/dialog/oauth'
oauth = OAuth()

UPLOAD_FOLDER = './static'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
# facebook configuration
facebook = oauth.remote_app('facebook',
                            base_url='https://graph.facebook.com/',
                            request_token_url=None,
                            access_token_url='/oauth/access_token',
                            authorize_url=AUTH_URL,
                            consumer_key=FACEBOOK_APP_ID,
                            consumer_secret=FACEBOOK_APP_SECRET,
                            request_token_params={'scope': 'email'}
                            )

app.register_blueprint(auth_blueprint)

login_manager = LoginManager()
login_manager.login_view = 'auth.login_register'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# route to display all categories and items
@app.route('/')
def index():
    categories = Category.query.all()
    items = Item.query.all()
    return render_template(
                            'index.html', categories=categories,
                            items=items, status_home="active")


@app.route('/fblogin')
def fb_login():
    return facebook.authorize(
                            callback=url_for(
                                            'facebook_authorized',
                                            next=request.args.get('next') or
                                            request.referrer or
                                            None, _external=True))


@app.route('/login/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['oauth_token'] = (resp['access_token'], '')
    session['logged_in'] = True
    me = facebook.get('/me')
    user = User.query.filter_by(email=me.data['name']).first()
    if user is None:
        new_user = User(
                    email=me.data['name'],
                    password=generate_password_hash('123456', method='sha256')
                    )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
    else:
        login_user(user)
    return redirect(url_for('index'))


''' Logged in as id=me.data['id'] name=me.data['name']
    redirect=request.args.get('next') '''


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')


# json endpoint to display all items
@app.route('/items.json')
def items_json():
    items = Item.query.all()
    return jsonify(items=[i.serialize for i in items])


# json endpoint to display all users
@app.route('/users.json')
def users_json():
    users = User.query.all()
    return jsonify(users=[i.serialize for i in users])


# json endpoint to display all categories
@app.route('/categories.json')
def categories_json():
    categories = Category.query.all()
    return jsonify(categories=[i.serialize for i in categories])


''' json endpoint to display items for certain category
    and checking if category or item exists or not'''


@app.route(
    '/categories/<int:category_id>/item/<int:item_id>')
def catalog_item_json(category_id, item_id):
    category = Category.query.filter_by(id=category_id).first()
    item = Item.query.filter_by(id=item_id).first()
    if category is None or item is None:
        error = 'item %d not found in category %d', item_id, category_id
        return jsonify(error='The item or the category does not exist.')
    items = Item.query.filter_by(id=item_id, cat_id=category_id).all()
    return jsonify(items=[i.serialize for i in items])


# route to html template for adding category
@app.route('/get_category', methods=['GET'])
def get_category():
    return render_template('add_category.html')


# route to add category
@app.route('/add_category', methods=['POST'])
@login_required
def add_category():
    title = request.form['category']
    cat_exists = Category.query.filter_by(
                                        user_id=current_user.id).filter_by(
                                                            name=title).first()
    if str(title) == '':
        flash("Category can\'t be empty", 'danger')
    elif cat_exists is None:
        file = request.files['file']
        upload()
        category = Category(name=title, user_id=current_user.id,
                            file_name=file.filename, data=file.read())
        db.session.add(category)
        db.session.commit()
        return redirect(url_for('index'))
    else:
        flash(title+" exists", 'danger')
    return redirect(url_for('get_category'))


# route to html template for adding item
@app.route('/get_item/<int:category_id>', methods=['GET', 'POST'])
@login_required
def get_item(category_id):
    categories = Category.query.filter_by(user_id=current_user.id).all()
    if request.method == 'GET':
        categories = Category.query.filter_by(user_id=current_user.id).all()
        return render_template('add_item.html', category_id=category_id)
    else:
        title = request.form['title']
        item_exists = Item.query.filter_by(
                                user_id=current_user.id, title=title).first()

        if str(title) == '':
            flash("Title can\'t be empty", 'danger')
        elif item_exists is None:
            description = request.form['description']
            file = request.files['file']
            upload()
            item = Item(
                        title=title, cat_id=category_id,
                        description=description, user_id=current_user.id,
                        file_name=file.filename, data=file.read())
            db.session.add(item)
            db.session.commit()
            return redirect(url_for(
                'show_category', category_id=category_id))
        else:
            flash(title+" exists", 'danger')
        return render_template('add_item.html', categories=categories)


# route to html template for displaying certain category
@app.route('/category/<int:category_id>')
def show_category(category_id):
    items = Item.query.filter_by(cat_id=category_id).all()
    return render_template('items.html', items=items, category_id=category_id)


# route to html template for showing certain item details
@app.route('/item/<int:item_id>')
def show_item(item_id):
    item = Item.query.filter_by(id=item_id).first()
    return render_template('show_item.html', item=item)


# route to html template for adding category
@app.route("/item/<int:item_id>/update/<int:cat_id>", methods=['GET', 'POST'])
@login_required
def edit_item(item_id, cat_id):
    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first()
    categories = Category.query.all()
    if not item or item.user_id != current_user.id:
        abort(403)
    if request.method == 'GET':
        return render_template(
                                'add_item.html', item=item,
                                category_id=cat_id)
    else:
        title = request.form['title']
        item_exists = Item.query.filter_by(
                                user_id=current_user.id, title=title).filter(
                                    Item.id != item.id).first()

        if str(title) == '':
            flash("Title can\'t be empty", 'danger')
        elif item_exists is None:

            item.title = request.form['title']
            item.description = request.form['description']
            item.cat_id = cat_id
            file = request.files['file']
            item.data = file.read()
            item.file_name = file.filename
            upload()

            db.session.commit()
            return redirect(url_for(
                'show_category', category_id=cat_id))
        else:
            flash(title+" exists", 'danger')
        return render_template(
                                'add_item.html', item=item,
                                categories=categories)


# route for deleting item
@app.route("/item/<int:item_id>/delete", methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    category_id = item.category_id.id
    if item.user_id != current_user.id:
        abort(403)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('show_category', category_id=category_id))


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)


def upload():
    # check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('uploaded_file', filename=filename))


if __name__ == '__main__':
    db.create_all()
    app.run(host='localhost', port=5000,
            ssl_context=('cert.pem', 'key.pem'))
