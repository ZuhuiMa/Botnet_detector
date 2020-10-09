# %%
import base64
import numpy as np
import os
import shutil
import matplotlib.pyplot as plt
from tensorflow import keras
from keras.preprocessing.image import ImageDataGenerator, load_img, img_to_array
from keras.preprocessing import image
from flask import url_for, render_template, request, jsonify, send_from_directory, redirect, flash
from tensorflow.keras.models import load_model
from flask_login import current_user, login_user, login_required, logout_user
from werkzeug.utils import secure_filename
import scapy.all as scapy
import math
import pandas as pd
# %%
img_1 = "../uploads/scan-portos-4-dec/TCP 172.217.161.72:443 > 192.168.0.23:50654.png"
data_1 = img_to_array(load_img(img_1)).astype('uint8')
data = np.expand_dims(data_1, axis=0)
model = load_model('../models/best_model.h5')


# %%

name = ['a','b','c']
value = [0,1,0]





# %%
