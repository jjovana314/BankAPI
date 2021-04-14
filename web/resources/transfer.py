from flask_restful import Resource
from flask import jsonify, request
from werkzeug.wrappers import BaseResponse
import exceptions
import helper
import config
import schemas
import operator


class Transfer(Resource):
    """ Transfer moeny from one account to another. """
    def post(self):
        """ Called when we have a POST request

        Returns:
            BaseResponse object with message and code
        """
        data = request.get_json()

        is_ok, result = helper.validation(schemas.transfer_schema, data)
        if not is_ok:
            return result
        users_exist = usr_ex1 and usr_ex2

        user_1_data = data["user1"]
        user_2_data = data["user2"]
        amount = data["amount"]

        username_1 = user_1_data["username"]
        username_2 = user_2_data["username"]
        try:
            helper.balance_validation(username_1, username_2)
        except ValueError as ex:
            return jsonify({"message": ex.args[0], "code": ex.args[1]})

        helper.update_balance(
            config.users, user_1_data["username"], amount, balance_acc1, operator.sub
        )
        helper.update_balance(
            config.users, user_2_data["username"], amount, balance_acc2, operator.add
        )

        helper.update_tokens(
            config.users, user_1_data["username"], 1, operator.sub
        )
        return jsonify(
            {
                "Message": "Transaction completed successfully.",
                "Code": config.OK
            }
        )
