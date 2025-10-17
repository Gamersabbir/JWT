import pymysql.cursors
from os import getenv

from dotenv import load_dotenv

load_dotenv()

def connect():
    return  pymysql.connect(host=getenv('DB_HOST'),
                                 user=getenv('DB_USER'),
                                 password=getenv('DB_PASSWORD'),
                                 database=getenv('DB_NAME'),
                                 charset='utf8mb4',
                                 cursorclass=pymysql.cursors.DictCursor)


def get_accounts(region):
    accounts = []
    connection = connect()
    with connection:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM guest_accounts WHERE region = %s"
            cursor.execute(sql, region)
            accounts = cursor.fetchall()

    return accounts


def store_account(account):
    connection = connect()
    with connection:
        with connection.cursor() as cursor:
            sql = "INSERT INTO guest_accounts (uid,password,token,token_expired_at,account_id,region,nickname,server_url) VALUES (%s, %s, %s, %s, %s, %s,%s,%s)"
            cursor.execute(sql, account)
        connection.commit()

    return account

def get_account(uid, password):
    connection = connect()
    account = {}
    with connection:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM guest_accounts WHERE uid = %s AND password = %s"
            cursor.execute(sql,[uid, password])
            account = cursor.fetchone()

    return account


def refresh_token(old_token,new_token,token_expired_at):
    connection = connect()
    with connection:
        with connection.cursor() as cursor:
          sql = "UPDATE guest_accounts SET token = %s,token_expired_at = %s WHERE token = %s"
          cursor.execute(sql,[new_token,token_expired_at,old_token])
        connection.commit()

    return True