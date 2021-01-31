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

        try:
            helper.validate_schema(schemas.loan_schema, data)
        except exceptions.SchemaError as ex:
            return jsonify(
                {
                    "message": "schema not match",
                    "code": config.SCHEMA_NOT_MATCH
                }
            )
        username = data["username"]
        password = data["password"]
        amount = data["amount"]
        usr_exist = helper.username_exist(config.users, username)
        if not usr_exist:
            return jsonify(
                {
                    "message": "this useranem does not exist",
                    "code": config.INVALID_USERNAME
                }
            )
        password_valid = helper.verify_password(
            config.users, password, username
        )
        if not password_valid:
            return jsonify(
                {
                    "message": "password you entered is not valid",
                    "code": config.INVALID_PASSWORD
                }
            )
        tokens = helper.count_tokens(config.users, username)
        if tokens <= 0:
            return jsonify(
                {
                    "message": "you don't have enough tokens, please refill",
                    "code": config.OUT_OF_TOKENS
                }
            )

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
            config.users, username, amount, balance_usr, operator.add
        )
        helper.update_balance(
            config.bank, config.bank_name, amount, balance_bank, operator.sub
        )
        helper.update_tokens(config.users, username, 1, operator.sub)
        return jsonify(
            {
                "Message": "Balance updated successfully.",
                "Code": config.OK
            }
        )
