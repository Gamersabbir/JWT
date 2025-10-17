import base64
import json
from datetime import datetime
from fake_useragent import UserAgent
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import os
import requests
from google.protobuf import json_format
from flask_cors import CORS, cross_origin
from helpers import json_to_proto, aes_cbc_encrypt, decode_protobuf, jwt_decode
from proto import FreeFire_pb2

load_dotenv()

MAIN_KEY = base64.b64decode(os.getenv("MAIN_KEY"))
MAIN_IV = base64.b64decode(os.getenv("MAIN_IV"))

app = Flask(__name__)
CORS(app, origins=["*"])  # সব origin থেকে access করার জন্য (shield-04.com বাদে)

# 🔹 Dummy storage (no MySQL)
accounts_cache = {}

def token_grant(uid, password):
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P9(ASUS_Z01QD ;Android 7.1.2;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
    }

    payload = {
        "client_secret": os.getenv("CLIENT_SECRET"),
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_id": os.getenv("CLIENT_ID"),
        "client_type": "2"
    }

    response = requests.post(
        "https://connect.garena.com/oauth/guest/token/grant",
        headers=headers,
        data=payload
    )

    if response.status_code == 200 and "access_token" in response.json():
        data = response.json()
        return {
            "access_token": data["access_token"],
            "open_id": data["open_id"],
        }

    return None


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/api/jwt-generate', methods=['GET'])
@cross_origin(origins=["*"])
def jwt_generate():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"message": "Missing parameters Uid and Password"}), 400

    # ✅ ১ম ধাপ: cache থেকে টোকেন থাকলে সরাসরি রিটার্ন
    if uid in accounts_cache and accounts_cache[uid]["token_expired_at"] > datetime.now():
        data = accounts_cache[uid]
        return jsonify({
            "account_id": data["account_id"],
            "nickname": data["nickname"],
            "region": data["region"],
            "access_token": data["token"],
            "token_expires": data["token_expired_at"],
            "api": data["server_url"],
            "credits": "https://discord.gg/HYZ7322Sta"
        })

    # ✅ ২য় ধাপ: নতুন টোকেন তৈরি
    account = token_grant(uid, password)
    if account is None:
        return jsonify({"message": "Account does not exist"}), 404

    ua = UserAgent().random
    headers = {
        "X-Unity-Version": "2018.4.11f1",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": ua,
        "Connection": "Keep-Alive",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
        "Accept-Encoding": "gzip"
    }

    payload = json.dumps({
        "open_id": account['open_id'],
        "open_id_type": "4",
        "login_token": account['access_token'],
        "orign_platform_type": "4"
    })

    proto_bytes = json_to_proto(payload, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    response = requests.post("https://loginbp.ggblueshark.com/MajorLogin", headers=headers, data=payload)

    msg = json.loads(json_format.MessageToJson(decode_protobuf(response.content, FreeFire_pb2.LoginRes)))
    jwt_infos = jwt_decode(msg['token'])

    # ✅ ৩য় ধাপ: cache-এ সেভ
    accounts_cache[uid] = {
        "account_id": msg['accountId'],
        "nickname": jwt_infos['nickname'],
        "region": msg["lockRegion"],
        "token": msg['token'],
        "token_expired_at": datetime.fromtimestamp(int(jwt_infos['exp'])),
        "server_url": msg['serverUrl']
    }

    return jsonify({
        "account_id": msg['accountId'],
        "nickname": jwt_infos['nickname'],
        "region": msg["lockRegion"],
        "access_token": msg['token'],
        "token_expires": datetime.fromtimestamp(int(jwt_infos['exp'])),
        "api": msg["serverUrl"],
        "credits": "https://discord.gg/HYZ7322Sta",
    })


# ✅ Vercel requires an app object named `app`
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
