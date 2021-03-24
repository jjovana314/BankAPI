register_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 1, "maxLength": 20},
        "password": {"type": "string", "minLength": 7, "maxLength": 50}
    },
    "additionalProperties": False,
    "required": ["username", "password"]
}

login_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 1, "maxLength": 20},
        "password": {"type": "string", "minLength": 7, "maxLength": 50},
        "sentance": {"type": "string", "minLength": 1, "maxLenth": 20}
    },
    "additionalProperties": False,
    "required": ["username", "password", "sentance"]
}

pass_change_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 1, "maxLength": 20},
        "password": {"type": "string", "minLength": 7, "mexLength": 50},
        "new_password": {"type": "string", "minLength": 7, "maxLength": 50}
    },
    "additionalProperties": False,
    "required": ["username", "password", "new_password"]
}

usr_change_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 1, "maxLength": 20},
        "password": {"type": "string", "minLength": 7, "mexLength": 50},
        "new_username": {"type": "string", "minLength": 1, "maxLength": 20}
    },
    "additionalProperties": False,
    "required": ["username", "password", "new_username"]
}

refill_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 1, "maxLength": 20},
        "admin_password": {"type": "string", "minLength": 12, "maxLength": 12},
        "amount": {"type": "number", "minimum": 0}
    },
    "additionalProperties": False
}

update_balance_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 1, "maxLength": 20},
        "password": {"type": "string", "minLength": 7, "mexLength": 50},
        "code": {"type": "string", "minLength": 1, "maxLength": 1},
        "amount": {"type": "number", "minimum": 0}
    },
    "additionalProperties": False,
    "required": ["username", "password", "code", "amount"]
}

transfer_schema = {
    "type": "object",
    "properties": {
        "user1": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 20
                },
                "password": {
                    "type": "string",
                    "minLength": 7,
                    "mexLength": 50
                },
            },
            "additionalProperties": False,
            "required": ["username", "password"]
        },
        "user2": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 20
                },
                "password": {
                    "type": "string",
                    "minLength": 7,
                    "mexLength": 50
                },
            },
            "additionalProperties": False,
            "required": ["username", "password"]
        },
        "amount": {"type": "number", "minimum": 0}
    },
    "additionalProperties": False,
    "required": ["user1", "user2", "amount"]
}

loan_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 1, "maxLength": 20},
        "password": {"type": "string", "minLength": 1, "maxLength": 50},
        "amount": {"type": "number", "minimum": 0}
    },
    "additionalProperties": False
}
