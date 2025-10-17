import base64
import json
import os
from datetime import datetime

import requests
from fake_useragent import UserAgent
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS, cross_origin
from google.protobuf import json_format
from dotenv import load_dotenv

from helpers import json_to_proto, aes_cbc_encrypt, decode_protobuf, jwt_decode
from proto import FreeFire_pb2
from mysql import get_account, store_account, refresh_token

load_dotenv()

MAIN_KEY = base64.b64decode(os.getenv("MAIN_KEY"))
MAIN_IV = base64.b64decode(os.getenv("MAIN_IV"))

app = Flask(__name__)
CORS(app, origins=["*"])  # allow all for testing


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
        "client_type": "2",
    }

    response = requests.post(
        "https://connect.garena.com/oauth/guest/token/grant",
        headers=headers,
        data=payload,
    )

    if response.status_code == 200 and "access_token" in response.json():
        data = response.json()
        return {"access_token": data["access_token"], "open_id": data["open_id"]}

    return None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/jwt-generate", methods=["GET"])
@cross_origin(origins=["*"])
def jwt_generate():
    uid = request.args.get("uid")
    password = request.args.get("password")

    if not uid or not password:
        return jsonify({"message": "Missing parameters Uid and Password"})

    exist_account = get_account(uid, password)

    if exist_account is not None and exist_account["token_expired_at"] > datetime.now():
        return jsonify(
            {
                "account_id": exist_account["account_id"],
                "nickname": exist_account["nickname"],
                "region": exist_account["region"],
                "access_token": exist_account["token"],
                "token_expires": exist_account["token_expired_at"],
                "api": exist_account["server_url"],
                "credits": "https://discord.gg/HYZ7322Sta",
            }
        )

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
        "Accept-Encoding": "gzip",
    }

    payload = json.dumps(
        {
            "open_id": account["open_id"],
            "open_id_type": "4",
            "login_token": account["access_token"],
            "orign_platform_type": "4",
        }
    )
    proto_bytes = json_to_proto(payload, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    response = requests.post(
        "https://loginbp.ggblueshark.com/MajorLogin", headers=headers, data=payload
    )
    msg = json.loads(
        json_format.MessageToJson(
            decode_protobuf(response.content, FreeFire_pb2.LoginRes)
        )
    )

    jwt_infos = jwt_decode(msg["token"])

    if exist_account is not None and exist_account["token_expired_at"] < datetime.now():
        refresh_token(
            exist_account["token"],
            msg["token"],
            datetime.fromtimestamp(int(jwt_infos["exp"])),
        )
    else:
        account_data = [
            uid,
            password,
            msg["token"],
            datetime.fromtimestamp(int(jwt_infos["exp"])),
            msg["accountId"],
            msg["lockRegion"],
            msg["serverUrl"],
            msg.get("nickname", "Unknown"),
        ]
        store_account(account_data)

    return jsonify(
        {
            "account_id": msg["accountId"],
            "region": msg["lockRegion"],
            "access_token": msg["token"],
            "token_expires": jwt_infos["exp"],
            "api": msg["serverUrl"],
            "credits": "Shield 04",
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
