from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
from helpers import *
from datetime import datetime
import requests
import json
from fake_useragent import UserAgent

app = Flask(__name__)
CORS(app)

@app.route('/api/jwt-generate', methods=['GET'])
@cross_origin(origins=["*"])  # চাইলে নির্দিষ্ট origin দিতে পারো

def jwt_generate():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"message": "Missing parameters Uid and Password"})

    # টোকেন নেওয়ার জন্য token_grant() ফাংশন ইউজ করা হচ্ছে
    account = token_grant(uid, password)
    if account is None:
        return jsonify({"message": "Account does not exist"})

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

    # এখানে কোনো ডাটাবেজে সেভ করা হচ্ছে না।
    # শুধু response JSON আকারে দেখানো হচ্ছে।
    return jsonify({
        "account_id": msg['accountId'],
        "nickname": jwt_infos['nickname'],
        "region": msg["lockRegion"],
        "access_token": msg['token'],
        "token_expires": datetime.fromtimestamp(jwt_infos['exp']),
        "api": msg["serverUrl"],
        "credits": "https://discord.gg/HYZ7322Sta"
    })


if __name__ == '__main__':
    app.run(debug=True)
