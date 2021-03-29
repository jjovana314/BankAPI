from flask_restful import Resource
from flask import jsonify, request
from werkzeug.wrappers import BaseResponse
import helper
import config
import schemas
import operator
import bcrypt


class PasswordChange(Resource):
    """ Called when user want to change their password. """
    def post(self) -> BaseResponse:
        """ Called when we have a POST requiest.

        Returns:
            BaseResponse instance with message and status for API
        """
        # try to get data from user
        data = request.get_json()
        helper.set_server_data(data)
        is_valid, result = helper.validation(schemas.pass_change_schema)
        if not is_valid:
            return jsonify(result)

        username, _, new_pwd = result

        new_pwd_hashed = bcrypt.hashpw(new_pwd.encode("utf-8"), bcrypt.gensalt())

        if helper.new_old_passwords_equal():
            return jsonify({"Message": "Old password cannot be new password", "Code": config.INVALID_PASSWORD})

        # removing one token
        helper.update_tokens(1, operator.sub)

        # changing password
        config.users.update({"Username": username}, {"$set": {"Password": new_pwd_hashed}})
        return jsonify({"status": config.OK, "msg": "Password changed succesfully."})
