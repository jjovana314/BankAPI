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
        data = request.get_json()

        is_valid, result = helper.validation(
            config.users, schemas.register_schema, data, config.keys_register,
            is_register=True
        )
        if not is_valid:
            return jsonify(result)
        else:
            username, password = result

        # crypt password for database
        # ! put this into smaller function
        if username == config.bank_name:
            return jsonify(
                {
                    "Message": "This username is taken.",
                    "Code": config.INVALID_USERNAME
                }
            )
        hashed_pw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())

        # data for bank
        password_bank_hashed = bcrypt.hashpw(
            config.bank_password.encode("utf8"), bcrypt.gensalt()
        )
        # ! put this into smaller function
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
        config.bank.insert(
            {
                "Username": config.bank_name,
                "Password": password_bank_hashed,
                "Balance": config.bank_balance
            }
        )
        return jsonify(
            {
                "Code": config.OK,
                "Message": "You succesfully signed up."
            }
        )
