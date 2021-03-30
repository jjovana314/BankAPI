import bcrypt
import exceptions
import operator
import config
import exception_messages as ex_msg
from http import HTTPStatus
from pymongo import MongoClient
from flask import request
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from json import dumps, loads


# TODO: finish testing

server_data_global = dict()


def set_server_data(server_data: dict) -> None:
    """ Get data from server and ser global variable.

    Arguments:
        server_data {dict} -- data from server
    """
    global server_data_global
    server_data_global = server_data


def get_username() -> str:
    """ Get username from server data.

    Returns:
        username from server data
    """
    return server_data_global["username"]


def get_admin_username() -> str:
    """ Get admin username from server data

    Returns:
        admin username from server data
    """
    return server_data_global["admin"]


def validate_schema(schema: dict) -> None:
    """ JSON schema validation.

    Arguments:
        schema {dict} -- valid dictionary

    Raises:
        SchemaError: if data dictionary is not valid
    """
    # we want json data, so we have to dump our data into json string
    data = dumps(server_data_global)
    try:
        # try to do validation for our json data
        validate(loads(data), schema)
    except ValidationError as ex:
        # ! here we do not except JSONDecodeError, remember that!
        ex_str = str(ex)
        for idx, value in enumerate(ex_msg.schema_errors):
            # create appropriate message for user
            # if there is exception occured
            if value in ex_str:
                raise ex_msg.schema_exceptions[idx](ex_msg.error_messages[idx])


def username_exist() -> bool:
    """ Check if username exist in database.

    Returns:
        bool -- True if username exist, False otherwise
    """
    return not (config.users.find({"Username": get_username()}).count() == 0)


def verify_password(password: str, username: str) -> bool:
    """ Password verification.

    Returns:
        bool -- True if password matches username, False otherwise
    """
    # check if username exist in database
    if not username_exist():
        return False

    password_db = config.users.find({"Username": username})[0]["Password"]
    password_encoded = password.encode("utf-8")
    hashed_pw = bcrypt.hashpw(password_encoded, password_db)
    return hashed_pw == password_db


def count_tokens() -> int:
    """ Token counting.

    Returns:
        int -- number of tokens
    """
    return config.users.find({"Username": get_username()})[0]["Tokens"]


def validate_tokens(code: int) -> None:
    """ Validate that user has enough tokens.

    Arguments:
        code {int} -- code for error

    Raises:
        TokensException: if user does not have enough tokens
    """
    if count_tokens() <= 0:
        raise exceptions.TokensException(
            "You are out of tokens, please refill.", code
        )


def validate_username(code: int) -> None:
    """ Validate that username exist in database.

    Arguments:
        code {int} -- code for error

    Raises:
        UserException: If username does not exist in database
    """
    if not username_exist():
        raise exceptions.UserException("This username does not exist.", code)


def update_tokens(tokens_update: int, operation: operator) -> None:
    """ Update tokens for user in database.

    Arguments:
        tokens_update {int} -- number of tokens for update
        operation {operator} -- operation that we want
                                to implement (sub or add)

    Raises:
        TokensException: if tokens_update is not integer or
                         if operation is not subtraction or addition
    """
    if not isinstance(tokens_update, int):
        raise exceptions.TokensException(
            "You can update tokens only with integer numbers",
            config.BAD_REQUEST
        )
    if not (operation is operator.sub or operation is operator.add):
        raise exceptions.TokensException(
            "You can only add or subtract tokens",
            BAD_REQUEST
        )
    tokens_current = count_tokens()
    config.users.update(
        {"Username": get_username()},
        {"$set": {"Tokens": operation(tokens_current, tokens_update)}}
    )


def update_balance(amount: float, money_curr: float, operation: operator) -> None:
    """ Update balance for account.

    Arguments:
        username {str} -- username
        amount {float} -- amount for balance update
        operation {operator} -- add or subtract

    Raises:
        UserException: if operation is not subtraction or addition
    """
    if not (operation is operator.sub or operation is operator.add):
        raise exceptions.UserException(
            "You can only add or subtract balance from account",
            config.BAD_REQUEST
        )
    config.users.update(
        {"Username": get_username()},
        {"$set": {"Balance": operation(money_curr, amount)}}
    )


error_usr_exist = "This username does not exist"
error_usr_notexist = "This username is taken"
error_pwd_msg = "Password you entered is not valid"
error_schema = "Schema not match"


def validation(schema: dict, is_register=False, token_validation=True) -> tuple:
    """ Validation for data dictionary.

    Arguments:
        schema {dict} -- schema for validation
        is_register {:obj:'boolean', optional} -- True if class Register is caller.
                                                  Default is False
        token_validation {:obj"'bolean', optional} -- False if caller does not want
                                                      to do token validation. Default is True

    Returns:
        tuple: boolean value (True if validation is OK, False otherwise)
                and message that explains error that occures,
                or values from data dictionary if data is valid
    """
    status, message_dict = schema_validation_caller(schema)
    if not status:
        return status, message_dict

    # if the class that our function is called by is not
    # Register class, we do the validation on specific way
    if not is_register:
        is_valid, message = inner_validation_caller(username_exist(), token_validation, schema)
        if not is_valid:
            return is_valid, message
    else:
        # if our caller is Register class
        # we want to report error if username exist in database
        if username_exist():
            return False, {"Message": error_usr_notexist, "Code": config.INVALID_USERNAME}

    return True, list(server_data_global.values())


def schema_validation_caller(schema: dict) -> tuple:
    """ Schema validation.

    Arguments:
        schema {dict} -- schema for validation

    Returns:
        tuple with:
            False if data is not valid and dictionary with message about error
            True if data is valid and None object
    """
    try:
        validate_schema(schema)
    except exceptions.SchemaError as ex:
        return False, {"Message": error_schema, "Code": config.SCHEMA_NOT_MATCH}
    else:
        return True, None


def inner_validation_caller(usr_exist: bool, token_validation: bool, schema: dict) -> tuple:
    """ Validate inner dictionary from server data.

    Arguments:
        usr_exist {bool} -- True if user exists in database, False otherwise
        token_validation {bool} -- True if we want to vallidate user's tokens, False otherwise
        schema {dict} -- schema for server_data validation

    Returns:
        Tuple with information about validation:
            False and dictionary about exception that occured,
            or True and None object if server data is valid
    """
    try:
        inner_data_validation(usr_exist, token_validation, schema)
    except exceptions.UserException as ex:
        return False, {"Message": ex.args[0], "Code": ex.args[1]}
    # if KeyError occures then we don't have admin password
    # in data dictionary
    except KeyError:
        return False, {"Message": "Admin password is missing", "Code": config.INVALID_PASSWORD}
    else:
        return True, None


values = []


def inner_data_validation(usr_exist: bool, token_validation: bool, schema: dict) -> None:
    """ Validate inner data from dictionary.

    Arguments:
        usr_exist {bool} -- True if user exist in database,
                            False otherwise
        token_validation {bool} -- True if user wants to validate
                                    tokens, False otherwise
        schema {dict} -- schema for validation

    Raises:
        UserException: if user does not exist in database
                       if password is not valid
                       if user that sends money does not have tokens
    """
    if not usr_exist:
        raise exceptions.UserException(error_usr_exist, config.INVALID_USERNAME)

    if is_value_dict():
        validate_password_dict()
    else:
        password_existance()
        raise_exception_if_password_invalid()

    # if admin wants to validate that there is enough
    # tokens for current user
    if token_validation:
        validate_tokens(config.OUT_OF_TOKENS)


def raise_exception_if_password_invalid() -> None:
    """ Raising PasswrodException if password is invalid. """
    if not password_validation_caller():
        raise exceptions.PasswordException("Please enter valid password", config.INVALID_PASSWORD)


def is_value_dict() -> bool:
    """ Check if value from outter dicionary is also dictionary.

    Returns:
        True if value is dictionary, False otherwise
    """
    return all([isinstance(value, dict) for value in list(server_data_global.values())])


def validate_password_dict() -> None:
    """ Validate password inside inner dictionary from server data.

    Raise:
        PasswordException if password is not valid
    """
    for value in list(server_data_globa.values()):
        if isinstance(value, dict):
            verification_all_pwd = verify_password(value["password"], get_username())
            password_invalid_exception_raising(verification_all_pwd)
            dictionary_apending(config.users, value)


def password_existance() -> str:
    """ Try to get password from server data and handling KeyError exception.

    Raise:
        PasswordException if password does not exist in server data

    Returns:
        password value from server if password exists
    """
    try:
        return server_data_global["password"]
    except KeyError:
        return admin_password_existance()


def admin_password_existance():
    try:
        return server_data_global["admin_password"]
    except KeyError:
        raise exceptions.PasswordException("Please enter password", config.INVALID_PASSWORD)


def password_validation_caller(username_key: str, password_key: str) -> bool:
    """ Calling password_validation function and catch exception.

    Return:
        True if password is valid, False otherwise
    """
    password_value = server_data_global.get(password_key)
    if password_value is not None:
        return verify_password(password_value, server_data_global[username_key])


def dictionary_apending(current_dict: dict) -> bool:
    """ Appending dictionaries to list.

    Arguments:
        current_dict {dict}: current dictionary

    Returns:
        True if all passwords are valid, False otherwise
    """
    global values
    if isinstance(current_dict, dict):
        # if value from data is dictionary
        values, verification_all_pwd = inner_dict_validation()
    else:
        values.append(current_dict)
        verification_all_pwd = password_validation_caller()

    return verification_all_pwd


def inner_dict_validation() -> tuple:
    """ Validation for inner dictionary.

    Returns:
        tuple: list with values from inner dictionary,
        username from first user, and validation for
        all passwords
    """
    usr_1 = server_data_global["user1"]["username"]
    pwd_1 = server_data_global["user1"]["password"]

    usr_2 = server_data_global["user2"]["username"]
    pwd_2 = server_data_global["user2"]["password"]

    verify_1 = verify_password(pwd_1, usr_1)
    verify_2 = verify_password(pwd_2, usr_2)
    verification_all_pwd = verify_1 and verify_2
    values = [usr_1, pwd_1, usr_2, pwd_2]

    return values, verification_all_pwd


def balance_validation(username_user1: str, username_user2: str) -> None:
    """ Balance validation.

    Arguments:
        username_user1 {str} -- user from whom we take the money
        username_user2 {str} -- user whom we pay the money

    Raises:
        ValueError: if user does not have enough money for transaction
    """
    balance_user1 = find_balance(username_user1)
    balance_user2 = find_balance(username_user2)
    if balance_user1 < balance_user2:
        raise ValueError(
            "You don't have enough money to perform this transaction", config.NOT_ENOUGH_MONEY
        )


def arguments_validation(server_values: list) -> tuple:
    """ Validate arguments from server dictionary.

    Arguments:
        server_values {list} -- values that we got from server

    Returns:
        Tuple with username and password if they exist,
        or dictionary with message and code and False if they are not in server_values
    """
    try:
        username, password = server_values
    except ValueError as ex:
        return {"Message": ex.args[0], "Code": config.BAD_REQUEST}, False
    else:
        return username, password


def new_old_passwords_equal() -> bool:
    global server_data_global
    return server_data_global["password"] == server_data_global["new_password"]
