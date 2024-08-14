from flask import Flask, jsonify
from flask_cors import CORS


app = Flask(__name__)
app.config.from_object(__name__)

CORS(app)

@app.route('/login', methods=['GET', 'POST'])
def sign_in():
    return jsonify('Logged successfully!')


if __name__ == '__main__':
    app.run()