import exceptions

schema_errors = [
    "Failed validating 'type' in schema",
    "Failed validating 'required' in schema",
    "Failed validating 'minLength' in schema",
    "Failed validating 'maxLength' in schema",
    "Failed validating 'minimum' in schema",
    "Failed validating 'maximum' in schema"
]

error_messages = [
    "Invalid type of data",
    "Please enter all required fields",
    "String length is less then minimum",
    "String length exceeded maximum",
    "Value is less then minimum",
    "Value is greater then maximum"
]

schema_exceptions = [
    exceptions.TypeSchemaError,
    exceptions.RequiredSchemaError,
    exceptions.MinLengthSchemaError,
    exceptions.MaxLengthSchemaError,
    exceptions.MinimumSchemaError,
    exceptions.MaximumSchemaError
]
