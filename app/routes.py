import base64
import numpy as np
import os
import shutil
import matplotlib.pyplot as plt
from tensorflow import keras
from keras.preprocessing.image import ImageDataGenerator, load_img, img_to_array
from keras.preprocessing import image
from flask import url_for, render_template, request, jsonify, send_from_directory, redirect, flash, send_file, make_response
from tensorflow.keras.models import load_model
from app import app, db
from flask_login import current_user, login_user, login_required, logout_user
from form import LoginForm, RegistrationForm
from app.models import User, Ct
from werkzeug.utils import secure_filename
import scapy.all as scapy
import math
import pandas as pd

UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']
STATIC_FOLDER = app.config['STATIC_FOLDER']
DOWNLOAD_FOLDER = app.config['DOWNLOAD_FOLDER']

print("Loading Model Now...\n")
model = load_model('models/best_model.h5')
print("Model loaded!!")
ALLOWED_EXTENSIONS = set(['pcap'])


def allowed_file(filename):
    return "." in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# flow -> png
def array_to_img(flow_load, dst_folder, file_name):
    flow_load = np.array((flow_load), dtype='uint8')
    if flow_load.shape[0] < 1024:
        num_pad = 1024 - flow_load.shape[0]
        flow_load = np.pad(flow_load, (0, num_pad),
                           'constant', constant_values=(0, 0))
    else:
        flow_load = flow_load[flow_load.shape[0]-1024:]
    gratImage = flow_load.reshape(32, 32)
    full_path = os.path.join(dst_folder, file_name)
    plt.imsave(full_path, gratImage, cmap='gray')


# 输入pcap文件，目标文件夹地址  -> 输出处理后的png文件
def pcap_to_png(pcap_file, target_folder):
    pcaps = scapy.rdpcap(pcap_file)
    for session_name, session_content in pcaps.sessions().items():  # extract session information
        total_size = 0
        total_load = []
        for packet in session_content:  # extract packets in a session
            if 'IP' not in packet:
                continue
            del(packet['Ether'].dst)
            del(packet['Ether'].src)
            del(packet['IP'].id)
            del(packet['IP'].src)
            del(packet['IP'].dst)
            total_size += len(packet.original)
            total_load += list(packet.original)
        total_duration = session_content[-1].time - session_content[0].time
        total_load.append(int(math.log(total_size+1, 1.1)))
        total_load.append(int(math.log(total_duration+1, 1.1)))
        array_to_img(flow_load=total_load, dst_folder=target_folder,
                     file_name=session_name+".png")


def api(full_path):
    data = img_to_array(load_img(full_path)).astype('uint8')
    data = np.expand_dims(data, axis=0)
    predicted = (model.predict(data) > 0.5).astype('int32')[0][0]
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
        # 如果已登录
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
        # 如果没登陆
        else:
            full_name = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(full_name)
            folder_name = os.path.join(
                UPLOAD_FOLDER, file.filename.split(".")[0])
            if os.path.exists(folder_name):
                print("Target Folder already exists!")
                shutil.rmtree(folder_name)
                print("Target Folder delected!")
            os.mkdir(folder_name)
            # pcap -> png
            pcap_to_png(pcap_file=full_name, target_folder=folder_name)
            pngs = [os.path.join(folder_name, file)
                    for file in os.listdir(folder_name)]
            tol_num = len(pngs)
            bot_num = 0
            predictions = []
            for png in pngs:
                if api(png):
                    predictions.append(1)
                    bot_num += 1
                else:
                    predictions.append(1)
            bot_per = round(bot_num/tol_num, 2)
            file_names = [file for file in os.listdir(folder_name)]
            result = pd.DataFrame(
                {'session_infomation': file_names, 'is_botnet': predictions})
            save_path = os.path.join(
                DOWNLOAD_FOLDER, file.filename.split(".")[0])
            result.to_csv(save_path, index=False)
    return render_template('predict.html', file_name=file.filename, bot_num=bot_num, tol_num=tol_num, bot_per=bot_per)


@app.route("/download", methods=['GET'])
def download_file(filename):
    # 需要知道2个参数, 第1个参数是本地目录的path, 第2个参数是文件名(带扩展名)
    directory = DOWNLOAD_FOLDER  # 假设在当前目录
    response = make_response(send_from_directory(
        directory, filename, as_attachment=True))
    response.headers["Content-Disposition"] = "attachment; filename={}".format(
        file_name.encode().decode('latin-1'))
    return response


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
