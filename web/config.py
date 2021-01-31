from http import HTTPStatus
from flask import Flask
from flask_restful import Api
from pymongo import MongoClient


OK = HTTPStatus.OK
BAD_REQUEST = HTTPStatus.BAD_REQUEST
INVALID_USERNAME = 301
INVALID_PASSWORD = 302
OUT_OF_TOKENS = 303
NOT_ENOUGH_MONEY = 304
INVALID_AMOUNT = 305
INVALID_CODE = 306
SCHEMA_NOT_MATCH = 307

tokens_start = 6        # number of tokens when user register

# global variables with valid keys
keys_register = ["username", "password"]
keys_login = ["username", "password", "sentance"]

password_change_keys = ["username", "password", "new_password"]
username_change_keys = ["username", "password", "new_username"]

refill_keys = ["username", "admin_password", "amount"]

update_balance_keys = ["username", "password", "code", "amount"]
loan_keys = ["username", "password", "amount"]

# bank data
bank_password = "xA5411q@!"
bank_balance = 2000
bank_name = "Bank_name"

admin_pwd = "abmnop.12.01"  # admin password for tokens refill
admin_name = "administrator"    # admin name for tokens refill

app = Flask(__name__)
api = Api(app)
client = MongoClient("mongodb://db:27017")
db = client.BankUsers
users = db["Users"]
bank = db["Bank"]
