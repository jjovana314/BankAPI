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
        admin_pwd_crypted = bcrypt.hashpw(config.admin_pwd.encode("utf8"), bcrypt.gensalt())
        config.users.insert({"Username": config.admin_name,"Password": admin_pwd_crypted})

        helper.set_server_data(request.get_json())

        validation, result = helper.validation(schemas.refill_schema, token_validation=False)
        if not validation:
            return jsonify(result)
        username, _, tokens_add = result

        helper.update_tokens(username, tokens_add, operator.add)
        return jsonify({"Message": "Tokens updated successfully.", "Code": config.OK})
