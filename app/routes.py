import base64
import numpy as np
import io
import os
import cv2
import tensorflow as tf
from tensorflow import keras
from keras.preprocessing.image import ImageDataGenerator, load_img, img_to_array
from keras.preprocessing import image
from flask import url_for, render_template, request, jsonify, send_from_directory, redirect, flash
from tensorflow.keras.models import load_model
import sys
from app import app, db
from flask_login import current_user, login_user, login_required, logout_user
from form import LoginForm, RegistrationForm
from app.models import User, Ct
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']
STATIC_FOLDER = app.config['STATIC_FOLDER']

print("Loading Model Now...\n")
model = load_model('models/best_model.h5')
# model_2 = load_model('models/EfficientNetB2_LuyaoLi.h5')
# model_3 = load_model('models/EfficientNetB2_zuhuima_1.h5')
# model_4 = load_model('models/EfficientNetB2_zuhuima_2.h5')
# models = [model_1, model_2, model_3, model_4]
# models = []
print("Model loaded!!")

ALLOWED_EXTENSIONS = set(['pcap'])

def allowed_file(filename):
    return "." in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def pcap_to_png(pcap_file):
    pass

def api(full_path):
    data = load_img(full_path, grayscale=False,
                    color_mode='rgb', target_size=(32, 32, 3))
    data = img_to_array(data)
    data = np.expand_dims(data, axis=0)
    predicted = model.predict(data)
    predicted = np.clip(predicted, 0, 1)
    predicted = predicted[0][0]
    return predicted


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    return render_template('index.html', title='Home page')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first_or_404()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template("login.html", title="Sign in", form=form)


@app.route('/upload', methods=['POST', 'GET'])
def upload_file():
    if request.method == 'GET':
        return render_template('index.html')
    else:
        file = request.files['pcap']
        if not allowed_file(file.filename):
            flash('Only pcap files can be uploaded')
            return redirect(url_for('index'))

        if current_user.is_authenticated:
            full_name = os.path.join(UPLOAD_FOLDER, str(current_user.id))
            if not os.path.exists(full_name):
                os.mkdir(full_name)
            full_name = os.path.join(full_name, file.filename)
            file.save(full_name)
            result = api(full_name)
            if result > 0.5:
                label = 'covid'
            else:
                result = 0
                label = 'noncovid'
            accuracy = round(result * 100, 5)
            ct = Ct(filename=file.filename, result=accuracy,
                    user_id=current_user.id)
            db.session.add(ct)
            db.session.commit()
        else:
            full_name = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(full_name)
            # result = api(full_name)
            # if result > 0.5:
            #     label = 'covid'
            # else:
            #     result = 0
            #     label = 'noncovid'
            # accuracy = round(result * 100, 5)
            label = "不错"
            accuracy = 0
    return render_template('predict.html', image_file_name=file.filename, label=label, accuracy=accuracy)


@login_required
@app.route('/history/<id>', methods=['POST', 'GET'])
def history(id):
    if int(id) != int(current_user.id):
        flash("Users are allowed to access their own upload history only")
        return redirect(url_for('index'))

    page = request.args.get('page', 1, type=int)
    cts = Ct.query.filter_by(user_id=id).order_by(Ct.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('index', page=cts.next_num) \
        if cts.has_next else None
    prev_url = url_for('index', page=cts.prev_num) \
        if cts.has_prev else None
    return render_template('history.html', id=id, cts=cts.items, next_url=next_url,
                           prev_url=prev_url)


@app.route('/uploads/<filename>', methods=['GET', 'POST'])
def send_file(filename):
    if current_user.is_authenticated:
        return send_from_directory("../%s/%s" % (UPLOAD_FOLDER, current_user.id), filename)
    return send_from_directory("../%s" % UPLOAD_FOLDER, filename)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template("register.html", title='Registration', form=form)
