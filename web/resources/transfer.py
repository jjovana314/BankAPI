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
        try:
            usr_ex1 = helper.username_exist(
                config.users, data["user1"]["username"]
            )
            usr_ex2 = helper.username_exist(
                config.users, data["user2"]["username"]
            )
        except KeyError:
            return jsonify(
                {
                    "Message": "Please enter valid data for users",
                    "Code": config.SCHEMA_NOT_MATCH
                }
            )
        users_exist = usr_ex1 and usr_ex2
        try:
            helper.inner_data_validation(
                users_exist, True, config.users,
                schemas.transfer_schema, data
            )
        except exceptions.UserException as ex:
            return jsonify(
                {
                    "Message": ex.args[0],
                    "Code": ex.args[1]
                }
            )
        user_1_data = data["user1"]
        user_2_data = data["user2"]
        amount = data["amount"]

        # todo: validate that account 1 has enough money
        balance_acc1 = config.users.find(
            {
                "Username": user_1_data["username"]
            }
        )[0]["Balance"]

        balance_acc2 = config.users.find(
            {
                "Username": user_2_data["username"]
            }
        )[0]["Balance"]

        if balance_acc1 < amount:
            return jsonify(
                {
                    "Message": ("You don't have enough money "
                                "for this transaction."),
                    "Code": config.NOT_ENOUGH_MONEY
                }
            )
        # todo: update balance on account 2
        helper.update_balance(
            config.users, user_1_data["username"], amount, balance_acc1, operator.sub
        )
        helper.update_balance(
            config.users, user_2_data["username"], amount, balance_acc2, operator.add
        )
        # todo: take token from account 1
        helper.update_tokens(
            config.users, user_1_data["username"], 1, operator.sub
        )
        return jsonify(
            {
                "Message": "Transaction completed successfully.",
                "Code": config.OK
            }
        )
