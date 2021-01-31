from flask_restful import Resource
from flask import jsonify, request
from werkzeug.wrappers import BaseResponse
import helper
import config
import schemas
import operator


class Login(Resource):
    """ Login existing user. """
    def post(self) -> BaseResponse:
        """ Called when we have a POST requiest.

        Returns:
            BaseResponse instance with message and status for API
        """
        data = request.get_json()

        is_valid, result = helper.validation(
            config.users, schemas.login_schema, data, config.keys_login
        )
        if not is_valid:
            return jsonify(result)
        else:
            username, _, sentance = result

        # updating Tokens and Sentance
        helper.update_tokens(config.users, username, 1, operator.sub)

        # update sentance in database
        config.users.update(
            {
                "Username": username
            },
            {
                "$set": {
                    "Sentance": sentance
                }
            }
        )
        return jsonify(
            {
                "status": config.OK,
                "msg": "You succesfully login.",
                "sentance": sentance
            }
        )
