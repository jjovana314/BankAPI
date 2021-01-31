from flask_restful import Resource
from flask import jsonify, request
from werkzeug.wrappers import BaseResponse
import helper
import config
import schemas
import operator


class PayLoan(Resource):
    """ Alow user to pay loan to bank. """
    def post(self):
        """ Called when we have a POST request

        Returns:
            BaseResponse object with message and code
        """
        data = request.get_json()
        is_valid, result = helper.validation(
            config.users, schemas.loan_schema, data, config.loan_keys
        )
        if not is_valid:
            return jsonify(result)
        username = data["username"]
        balance_usr = config.users.find(
            {
                "Username": username
            }
        )[0]["Balance"]
        amount = data["amount"]
        if amount > balance_usr:
            return jsonify(
                {
                    "Message": "You don't have enough money to pay loan.",
                    "Code": config.NOT_ENOUGH_MONEY
                }
            )
        bank_balance = config.bank.find(
            {
                "Username": config.bank_name
            }
        )[0]["Balance"]
        helper.update_balance(
            config.bank, config.bank_name, amount, bank_balance, operator.add
        )
        helper.update_balance(
            config.users, username, amount, balance_usr, operator.sub
        )
        return jsonify(
            {
                "Message": "Transaction successfully terminated.",
                "Code": config.OK
            }
        )
