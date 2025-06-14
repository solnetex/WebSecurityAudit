from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os

app = Flask(__name__, static_folder='static')
CORS(app)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '')
    result = {
        'url': url,
        'status': 'OK',
        'issues_found': 0,
        'message': 'Basic scan successful!'
    }
    return jsonify(result)

# Serve frontend static files
@app.route('/', defaults={'path': 'index.html'})
@app.route('/<path:path>')
def serve_frontend(path):
    return send_from_directory(app.static_folder, path)

if __name__ == '__main__':
    app.run(debug=True)
