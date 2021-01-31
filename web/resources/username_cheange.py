from flask_restful import Resource
from flask import jsonify, request
from werkzeug.wrappers import BaseResponse
import helper
import config
import schemas
import operator


class UsernameChange(Resource):
    """ Called when user want to change their username. """
    def post(self) -> BaseResponse:
        """ Called when we have a POST requiest.

        Returns:
            BaseResponse instance with message and status for API
        """
        # try to get data from user
        data = request.get_json()

        is_valid, result = helper.validation(
            config.users, schemas.usr_change_schema,
            data, config.username_change_keys
        )
        if not is_valid:
            return jsonify(result)
        username, _, new_username = result

        # removing one token
        helper.update_tokens(config.users, username, 1, operator.sub)
        config.users.update(
            {
                "Username": username
            },
            {
                "$set":
                    {
                        "Username": new_username
                    }
            }
        )

        return jsonify(
            {
                "Message": "Username changed successfully.",
                "Code": config.OK
            }
        )
