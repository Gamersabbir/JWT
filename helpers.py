import base64
import json
from Crypto.Cipher import AES
from google.protobuf import json_format
import FreeFire_pb2
import jwt
import os

MAIN_KEY = os.getenv("MAIN_KEY")
MAIN_IV = os.getenv("MAIN_IV")

def pad(data: bytes):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def aes_cbc_encrypt(key, iv, plaintext):
    cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, bytes.fromhex(iv))
    return cipher.encrypt(pad(plaintext))

def json_to_proto(json_data, proto_message):
    if isinstance(json_data, str):
        json_data = json.loads(json_data)
    json_format.ParseDict(json_data, proto_message)
    return proto_message.SerializeToString()

def decode_protobuf(data, proto_class):
    msg = proto_class()
    msg.ParseFromString(data)
    return msg

def jwt_decode(token):
    return jwt.decode(token, options={"verify_signature": False})

def token_grant(uid, password):
    # Placeholder function — এখানে API কল করে token generate করা হবে।
    # এখন শুধুমাত্র উদাহরণস্বরূপ fake ডেটা রিটার্ন করছে।
    return {
        "open_id": uid,
        "access_token": password
    }
