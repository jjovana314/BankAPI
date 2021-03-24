from flask_restful import Resource
from flask import request, jsonify
from werkzeug.wrappers import BaseResponse
import config
import bcrypt
import helper
import schemas


class Register(Resource):
    """ Register new user. """
    def post(self) -> BaseResponse:
        """ Called when we have a POST requiest.

        Returns:
            BaseResponse instance with message and status for API
        """
        server_data = request.get_json()
        is_valid, register_server_data = helper.validation(
            schemas.register_schema, server_data, is_register=True
        )
        if not is_valid:
            return jsonify(register_server_data)

        username_or_dict, password_or_false = helper.arguments_validation(register_server_data)
        if isinstance(password_or_false, bool):
            # username_or_dict is dict with error message and code
            return jsonify(username_or_dict)

        username, password = username_or_dict, password_or_false

        if username == config.bank_name:
            return jsonify(
                {"Message": "This username is taken.", "Code": config.INVALID_USERNAME}
            )

        insert_register_data(username, password)
        insert_bank_configuragion()

        return jsonify({"Code": config.OK,"Message": "You succesfully signed up."})


def insert_register_data(username, hashed_pw):
    config.users.insert(
        {
            "Username": username,
            "Password": hashed_pw,
            "Tokens": config.tokens_start,
            "Balance": 0,
            "Loan": 0,
            "Sentance": ""
        }
    )


def insert_bank_configuragion():
    config.bank.insert(
        {
            "Username": config.bank_name,
            "Password": bank_pwd_hashing(),
            "Balance": config.bank_balance
        }
    )


def bank_pwd_hashing():
    return bcrypt.hashpw(config.bank_password.encode("utf8"), bcrypt.gensalt())
