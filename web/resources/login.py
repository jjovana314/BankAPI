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
        helper.set_server_data(data)

        is_valid, result = helper.validation(schemas.login_schema)
        if not is_valid:
            return jsonify(result)
        else:
            username, _, sentence = result

        # updating Tokens and Sentance
        helper.update_tokens(1, operator.sub)

        # update sentance in database
        config.users.update(
            {"Username": username},
            {"$set": {"Sentance": sentence}}
        )
        return jsonify(
            {"status": config.OK, "msg": "You succesfully login.", "sentance": sentence}
        )
