from flask_restful import Resource
from flask import jsonify, request
import helper
import config
import schemas
import operator


class UpdateBalance(Resource):
    """ Updating account balance.

    Returns:
        BaseResponse object with message and code
    """
    def post(self):
        """ Called when we have a POST request.

        Returns:
            BaseResponse object with message and code
        """
        # taking data from server
        data = request.get_json()

        validation, result = helper.validation(
            config.users, schemas.update_balance_schema,
            data, config.update_balance_keys
        )

        if not validation:
            return jsonify(result)
        username, _, code, amount = result

        # add deposit to current money
        money_curr = config.users.find(
            {
                "Username": username
            }
        )[0]["Balance"]

        if amount <= 0:
            return jsonify(
                {
                    "Message": "Amount must be greather than zero.",
                    "Code": config.INVALID_AMOUNT
                }
            )
        # if code that is sent from user is not
        # 'D' for deposit or 'W' for withdraw
        # than we want to sent error to user
        # otherwise, we want to preform operation (deposit or withdraw)
        if code == "D":
            helper.update_balance(
                config.users, username, amount, money_curr, operator.add
            )
        elif code == "W":
            if amount > money_curr:
                return jsonify(
                    {
                        "Message": "You don't have enough money",
                        "Code": config.NOT_ENOUGH_MONEY
                    }
                )
            helper.update_balance(
                config.users, username, amount, money_curr, operator.sub
            )
        else:
            return jsonify(
                {
                    "Message": "For withdraw enter 'W', for deposit enter 'D'",
                    "Code": config.INVALID_CODE
                }
            )

        # remove one token
        helper.update_tokens(config.users, username, 1, operator.sub)
        return jsonify(
            {
                "Message": "You successfully updated your balance.",
                "Code": config.OK
            }
        )
