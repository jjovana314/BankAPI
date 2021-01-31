import bcrypt
import exceptions
import operator
import config
from exception_messages import (
    schema_errors, error_messages, schema_exceptions
)
from http import HTTPStatus
from pymongo import MongoClient
from flask import request
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from json import dumps, loads


# TODO: fix bug in inner_data_validation function


def validate_schema(schema: dict, data: dict) -> None:
    """ JSON schema validation.

    Arguments:
        schema {dict} -- valid dictionary
        data {dict} -- dictionary for validation

    Raises:
        SchemaError: if data dictionary is not valid
    """
    # we want json data, so we have to dump our data into json string
    data = dumps(data)
    try:
        # try to do validation for our json data
        validate(loads(data), schema)
    except ValidationError as ex:
        # ! here we do not except JSONDecodeError, remember that!
        ex_str = str(ex)
        for idx, value in enumerate(schema_errors):
            # create appropriate message for user
            # if there is exception occured
            if value in ex_str:
                raise schema_exceptions[idx](error_messages[idx])


def username_exist(users: MongoClient, username: str) -> bool:
    """ Check if username exist in database.

    Arguments:
        users {MongoClient} -- database
        username {str} -- username

    Returns:
        bool -- True if username exist, False otherwise
    """
    if users.find({"Username": username}).count() == 0:
        return False
    return True


def verify_password(
    users: MongoClient, password: str, username: str
) -> bool:
    """ Password verification.

    Arguments:
        users {MongoClient} -- database
        password {str} -- password

    Returns:
        bool -- True if password matches username, False otherwise
    """
    # check if username exist in database
    if not username_exist(users, username):
        return False

    password_db = users.find(
        {
            "Username": username
        }
    )[0]["Password"]

    hashed_pw = bcrypt.hashpw(
        password.encode("utf8"), password_db
    )
    return hashed_pw == password_db


def count_tokens(users: MongoClient, username: str) -> int:
    """ Token counting.

    Arguments:
        users {MongoClient} -- database
        username {str} -- username

    Returns:
        int -- number of tokens
    """
    return users.find(
        {
            "Username": username
        }
    )[0]["Tokens"]


def validate_tokens(
    users: MongoClient, username: str, code: int
) -> None:
    """ Validate that user has enough tokens.

    Arguments:
        users {MongoClient} -- database
        username {str} -- username
        code {int} -- code for error

    Raises:
        TokensException: if user does not have enough tokens
    """
    if count_tokens(users, username) <= 0:
        raise exceptions.TokensException(
            "You are out of tokens, please refill.", code
        )


def validate_username(
    users: MongoClient, username: str, code: int
) -> None:
    """ Validate that username exist in database.

    Arguments:
        users {MongoClient} -- database
        username {str} -- username
        code {int} -- code for error

    Raises:
        UserException: If username does not exist in database
    """
    if not username_exist(users, username):
        raise exceptions.UserException("This username does not exist.", code)


def update_tokens(
    users: MongoClient, username: str,
    tokens_update: int, operation: operator
) -> None:
    """ Update tokens for user in database.

    Arguments:
        users {MongoClient} -- database
        username {str} -- username
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
    tokens_current = count_tokens(users, username)
    users.update(
        {
            "Username": username
        },
        {
            "$set": {
                "Tokens": operation(tokens_current, tokens_update)
            }
        }
    )


def update_balance(
    users: MongoClient, username: str, amount: float,
    money_curr: float, operation: operator
) -> None:
    """ Update balance for account.

    Arguments:
        users {MongoClient} -- database
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
    users.update(
        {
            "Username": username
        },
        {
            "$set": {
                "Balance": operation(money_curr, amount)
            }
        }
    )


error_usr_exist = "This username does not exist"
error_usr_notexist = "This username is taken"
error_pwd_msg = "Password you entered is not valid"
error_schema = "Schema not match"


def validation(
    users: MongoClient, schema: dict, data: dict, keys: list,
    is_register=False, token_validation=True
) -> tuple:
    """ Validation for data dictionary.

    Arguments:
        users {MongoClient} -- database
        schema {dict} -- schema for validation
        data {dict} -- data dictionary for validation
        keys {list} -- list with valid keys
        is_register {:obj:'boolean', optional} -- True if class Register is caller.
                                                  Default is False
        token_validation {:obj"'bolean', optional} -- False if caller does not want
                                                      to do token validation. Default is True

    Returns:
        tuple: boolean value (True if validation is OK, False otherwise)
                and message that explains error that occures,
                or values from data dictionary if data is valid
    """
    # user data validation
    status, message_dict = validate_schema(data, schema)
    if not status:
        return status, message_dict
    values = list(data.values())
    username = data["username"]
    # validate userame existance
    usr_exist = username_exist(users, username)

    # if the class that our function is called by is not
    # Register class, we do the validation on specific way
    if not is_register:
        inner_validation_caller(usr_exist, token_validation, users, schema, data)
    else:
        # if our caller is Register class
        # we want to report error if username exist
        # in database
        if usr_exist:
            return (False, {
                "Message": error_usr_notexist,
                "Code": config.INVALID_USERNAME
            })

    return True, values


def schema_validation(data: dict, schema: dict) -> tuple:
    """ Schema validation.

    Arguments:
        data {dict} -- dictionary with all data
        schema {dict} -- schema for validation

    Returns:
        tuple with:
            False if data is not valid and dictionary with message about error
            True if data is valid and None object
    """
    try:
        validate_schema(schema, data)
    except exceptions.SchemaError as ex:
        return (False, {
            "Message": error_schema,
            "Code": config.SCHEMA_NOT_MATCH
        })
    else:
        return True, None


def inner_validation_caller(usr_exist, token_validation, users, schema, data):
    try:
        inner_data_validation(
            usr_exist, token_validation, users, schema, data
        )
    except exceptions.UserException as ex:
        return (False, {
            "Message": ex.args[0],
            "Code": ex.args[1]
        })
    # if KeyError occures then we don't have admin password
    # in data dictionary
    except KeyError:
        return (False,{
            "Message": "Admin password is missing",
            "Code": config.BAD_REQUEST
            })


values = []


def inner_data_validation(
    usr_exist: bool, token_validation: bool, users: MongoClient,
    schema: dict, data: dict
) -> None:
    """ Validate inner data from dictionary.

    Arguments:
        usr_exist {bool} -- True if user exist in database,
                            False otherwise
        token_validation {bool} -- True if user wants to validate
                                    tokens, False otherwise
        users {MongoClient} -- database
        schema {dict} -- schema for validation
        data {dict} -- data for validation

    Raises:
        UserException: if user does not exist in database
                       if password is not valid
                       if user that sends money does not have tokens
    """
    global values
    validate_schema(schema, data)
    values_list = list(data.values())

    for dictionary in values_list:
        verification_all_pwd = dictionary_appending(users, data, dictionary)

    if not usr_exist:
        raise exceptions.UserException(error_usr_exist, config.INVALID_USERNAME)

    if not verification_all_pwd:
        raise exceptions.UserException(error_pwd_msg, config.INVALID_PASSWORD)

    # if admin wants to validate that there is enough
    # tokens for current user
    if token_validation:
        validate_tokens(users, values[0], config.OUT_OF_TOKENS)


def password_validation_caller(users: MongoClient, data: dict, user: str) -> bool:
    """ Calling password_validation function and catch exception.

    Arguments:
        users {MongoClient}: users database
        data {dict}: dictionary with all data
        user {str}: user's name in database

    Return:
        True if password is valid, False otherwise
    """
    try:
        return verify_password(users, data["password"], user)
    except KeyError: 
        return verify_password(users, data["admin_password"], "administrator")


def dictionary_appending(users: MongoClient, data: dict, current_dict: dict) -> bool:
    """ Appending dictionaries to list.

    Arguments:
        users {MongoClient}: database
        data {dict}: dictionary with all data
        current_dict {dict}: current dictionary

    Returns:
        True if all passwords are valid, False otherwise
    """
    global values
    if isinstance(current_dict, dict):
            # if value from data is dictionary
            values, verification_all_pwd = inner_dict_validation(users, data)
    else:
        values.append(current_dict)
        user = data.get("username", None)
        if user is not None:
            verification_all_pwd = password_validation_caller(users, data, user)
    return verification_all_pwd


def inner_dict_validation(
    users: MongoClient, data: dict
) -> tuple:
    """ Validation for inner dictionary.

    Arguments:
        users {MongoClient} -- database
        data {dict} -- outter dictioanry

    Returns:
        tuple: list with values from inner dictionary,
        username from first user, and validation for
        all passwords
    """
    usr_1 = data["user1"]["username"]
    pwd_1 = data["user1"]["password"]

    usr_2 = data["user2"]["username"]
    pwd_2 = data["user2"]["password"]

    verify_1 = verify_password(users, pwd_1, usr_1)
    verify_2 = verify_password(users, pwd_2, usr_2)
    verification_all_pwd = verify_1 and verify_2
    values = [usr_1, pwd_1, usr_2, pwd_2]

    return values, verification_all_pwd
