from flask_restful import Resource
from flask import jsonify, request
from werkzeug.wrappers import BaseResponse
import helper
import config
import schemas
import operator
import bcrypt


class Refill(Resource):
    """ Refill tokens. """
    def post(self) -> BaseResponse:
        """ Called when we have a POST request.

        Returns:
            BaseResponse object with message and code
        """
        # crypting admin password (global variable)
        admin_pwd_crypted = bcrypt.hashpw(
            config.admin_pwd.encode("utf8"), bcrypt.gensalt()
        )
        config.users.insert(
            {
                "Username": config.admin_name,
                "Password": admin_pwd_crypted
            }
        )

        # get data
        data = request.get_json()

        validation, result = helper.validation(
            config.users, schemas.refill_schema, data,
            config.refill_keys, token_validation=False
        )
        if not validation:
            return jsonify(result)
        username, _, tokens_add = result

        # adding tokens
        helper.update_tokens(config.users, username, tokens_add, operator.add)
        return jsonify(
            {
                "Message": "Tokens updated successfully.",
                "Code": config.OK
            }
        )
