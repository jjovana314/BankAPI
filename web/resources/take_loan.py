from flask_restful import Resource
from flask import jsonify, request
from werkzeug.wrappers import BaseResponse
import helper
import config
import schemas
import operator
import exceptions


class TakeLoan(Resource):
    """ Take loan from bank. """
    def post(self):
        """ Called when we have a POST request

        Returns:
            BaseResponse object with message and code
        """
        data = request.get_json()

        is_ok, result = helper.validation(schemas.loan_schema, data)
        if not is_ok:
            return result
        username = data["username"]
        password = data["password"]
        amount = data["amount"]

        # ! repeatable code
        balance_usr = config.users.find(
            {
                "Username": username
            }
        )[0]["Balance"]
        balance_bank = config.bank.find(
            {
                "Username": config.bank_name
            }
        )[0]["Balance"]
        if balance_bank < amount:
            return jsonify(
                {
                    "Message": "You cannot take this amount of money",
                    "Code": config.NOT_ENOUGH_MONEY
                }
            )
        helper.update_balance(
            username, amount, balance_usr, operator.add
        )
        helper.update_balance(
            config.bank_name, amount, balance_bank, operator.sub
        )
        helper.update_tokens(config.users, username, 1, operator.sub)
        return jsonify(
            {
                "Message": "Balance updated successfully.",
                "Code": config.OK
            }
        )
