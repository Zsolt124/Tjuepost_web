from flask import Flask, render_template, request, redirect, url_for, session, flash
import json
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash

# secret key for sessions
SECRET_KEY = os.environ.get('TJUEPOST_SECRET') or 'dev-secret-change-me'

app = Flask(__name__)
app.secret_key = SECRET_KEY


@app.route('/')
def home():
    # load posts
    posts = []
    posts_file = os.path.join(os.path.dirname(__file__), 'posts.json')
    try:
        with open(posts_file, 'r', encoding='utf-8') as f:
            posts = json.load(f)
    except Exception:
        posts = []
    return render_template('home.html', posts=posts)

@app.route('/about')
def about():
    return '<h2>About Tjuepost.com</h2><p>This is the about page. More info coming soon!</p>'


@app.route('/new', methods=['GET'])
def new_post():
    # require login
    if 'user' not in session:
        flash('Please log in to create a post.')
        return redirect(url_for('login'))
    # require admin
    if not session.get('is_admin'):
        flash('Only site admins can create posts.')
        return redirect(url_for('home'))
    return render_template('new.html')


@app.route('/create', methods=['POST'])
def create_post():
    title = request.form.get('title', '').strip()
    body = request.form.get('body', '').strip()
    if not title and not body:
        return redirect(url_for('home'))

    # only admins may create posts
    if not session.get('is_admin'):
        flash('Only site admins can create posts.')
        return redirect(url_for('home'))

    posts_file = os.path.join(os.path.dirname(__file__), 'posts.json')
    try:
        with open(posts_file, 'r', encoding='utf-8') as f:
            posts = json.load(f)
    except Exception:
        posts = []

    post = {
        'id': int(datetime.utcnow().timestamp()),
        'title': title,
        'body': body,
        'created': datetime.utcnow().isoformat() + 'Z'
    }
    # add author if logged in (and include whether they're admin)
    if 'user' in session:
        post['author'] = session['user']
        post['author_is_admin'] = bool(session.get('is_admin'))
    posts.insert(0, post)

    with open(posts_file, 'w', encoding='utf-8') as f:
        json.dump(posts, f, ensure_ascii=False, indent=2)

    return redirect(url_for('home'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    username = request.form.get('username','').strip()
    password = request.form.get('password','')
    if not username or not password:
        flash('Provide username and password')
        return redirect(url_for('signup'))

    users_file = os.path.join(os.path.dirname(__file__), 'users.json')
    try:
        with open(users_file, 'r', encoding='utf-8') as f:
            users = json.load(f)
    except Exception:
        users = []

    if any(u['username']==username for u in users):
        flash('Username already exists')
        return redirect(url_for('signup'))

    # check admin code (optional) to mark the account as admin
    admin_code = request.form.get('admin_code', '').strip()
    admin_secret = os.environ.get('TJUEPOST_ADMIN_CODE')
    is_admin = False
    if admin_code and admin_secret and admin_code == admin_secret:
        is_admin = True

    users.append({'username': username, 'password': generate_password_hash(password), 'is_admin': is_admin})
    with open(users_file, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

    session['user'] = username
    session['is_admin'] = is_admin
    flash('Account created and logged in')
    return redirect(url_for('home'))


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form.get('username','').strip()
    password = request.form.get('password','')
    users_file = os.path.join(os.path.dirname(__file__), 'users.json')
    try:
        with open(users_file, 'r', encoding='utf-8') as f:
            users = json.load(f)
    except Exception:
        users = []

    user = next((u for u in users if u['username']==username), None)
    if not user or not check_password_hash(user['password'], password):
        flash('Invalid credentials')
        return redirect(url_for('login'))

    session['user'] = username
    session['is_admin'] = user.get('is_admin', False)
    flash('Logged in')
    return redirect(url_for('home'))





@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out')
    return redirect(url_for('home'))


@app.route('/admin', methods=['GET'])
def admin_panel():
    if not session.get('is_admin'):
        flash('Admin panel is for site admins only')
        return redirect(url_for('home'))
    users_file = os.path.join(os.path.dirname(__file__), 'users.json')
    try:
        with open(users_file, 'r', encoding='utf-8') as f:
            users = json.load(f)
    except Exception:
        users = []
    # normalize for template
    users_norm = [{'username': u.get('username'), 'is_admin': u.get('is_admin', False)} for u in users]
    return render_template('admin.html', users=users_norm)


@app.route('/admin/toggle', methods=['POST'])
def admin_toggle():
    if not session.get('is_admin'):
        flash('Admin action not allowed')
        return redirect(url_for('home'))
    target = request.form.get('username')
    users_file = os.path.join(os.path.dirname(__file__), 'users.json')
    try:
        with open(users_file, 'r', encoding='utf-8') as f:
            users = json.load(f)
    except Exception:
        users = []
    changed = False
    for u in users:
        if u.get('username') == target and u.get('username') != session.get('user'):
            u['is_admin'] = not bool(u.get('is_admin', False))
            changed = True
            break
    if changed:
        with open(users_file, 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
        flash('User updated')
    else:
        flash('No changes made')
    return redirect(url_for('admin_panel'))

@app.route('/Desboard')
def desboard():
    return '<h2>Desboard</h2><p>This is the Desboard page. More info coming soon!</p>'


if __name__ == '__main__':
    # When running under some debuggers (like VS Code's debugpy), the
    # Werkzeug auto-reloader can cause a SystemExit with code 3. Disable
    # the reloader when running from the debugger to avoid that.
    app.run(host='0.0.0.0', port=2000, debug=True, use_reloader=False)