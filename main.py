#!/usr/bin/python

import os
from flask import Flask, render_template

#initialization

app = Flask(__name__)
app.config.update(
     DEBUG = True,
)

#controllers
@app.route('/')
def hello():
    return render_template('index.html')

#launch
if __name__== "__main__":
    port=80
    app.run(host='0.0.0.0',port=port)

