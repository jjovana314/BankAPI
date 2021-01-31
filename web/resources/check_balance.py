from flask_restful import Resource
from flask import jsonify, request
import helper
import config
import schemas
import operator
import exceptions


# for balance we use register keys and register schema
class CheckBalance(Resource):
    """ Checking balance on user account. """
    def post(self):
        """ Called when we have a POST request.

        Returns:
            BaseResponse object with message and code
        """
        data = request.get_json()
        database = config.users

        valid, result = helper.validation(
            database, schemas.register_schema,
            data, config.keys_register
        )
        if not valid:
            # checking balance for bank account
            database = config.bank
            valid, result = helper.validation(
                database, schemas.register_schema,
                data, config.keys_register, token_validation=False
            )
            # set database to bank
            if not valid:
                return jsonify(result)
        username, _ = result
        balance = database.find(
            {
                "Username": username
            }
        )[0]["Balance"]
        if database is config.users:
            helper.update_tokens(
                database, username, 1, operator.sub
            )

        return jsonify(
            {
                "Message": f"Your balance is: {balance}",
                "Code": config.OK
            }
        )
