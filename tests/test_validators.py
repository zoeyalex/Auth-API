import pytest
from validators import (
    BodyValidator,
    RegisterValidator,
    LoginValidator,
    QueryParamsValidator,
    ActivateValidator,
)

# -------------------- BodyValidator Tests --------------------

@pytest.fixture
def body_validator():
    return BodyValidator(required_fields={'a', 'b'})

@pytest.mark.parametrize(
    "body, expected",
    [
        ({"a": 1, "b": 2}, (True, None)),
        ({}, (False, "Empty body")),
        ({"a": 1}, (False, "Missing required field: b")),
        ({"b": 2}, (False, "Missing required field: a")),
        ({"a": 1, "b": 2, "c": 3}, (False, "Unexpected fields in body")),
    ],
)
def test_body_validator(body_validator, body, expected):
    assert body_validator.validate(body) == expected

# -------------------- RegisterValidator Tests --------------------

@pytest.fixture
def register_validator():
    return RegisterValidator()

@pytest.mark.parametrize(
    "body, expected",
    [
        # Valid input: all required fields provided and pass regex checks.
        (
            {"username": "validuser", "email": "user@example.com", "password": "ValidPass1"},
            (True, None),
        ),
        # Missing field: email.
        (
            {"username": "validuser", "password": "ValidPass1"},
            (False, "Missing required field: email"),
        ),
        # Extra field: unexpected key in body.
        (
            {"username": "validuser", "email": "user@example.com", "password": "ValidPass1", "extra": "unexpected"},
            (False, "Unexpected fields in body"),
        ),
        # Invalid username: too short.
        (
            {"username": "short", "email": "user@example.com", "password": "ValidPass1"},
            (False, "Username must be 8-20 characters long"),
        ),
        # Invalid email format.
        (
            {"username": "validuser", "email": "invalidemail", "password": "ValidPass1"},
            (False, "Invalid email"),
        ),
        # Invalid password: too short.
        (
            {"username": "validuser", "email": "user@example.com", "password": "short"},
            (False, "Password must be 8-20 characters long"),
        ),
    ],
)
def test_register_validator(register_validator, body, expected):
    assert register_validator.validate(body) == expected

# -------------------- LoginValidator Tests --------------------

@pytest.fixture
def login_validator():
    return LoginValidator()

@pytest.mark.parametrize(
    "body, expected",
    [
        ({"username": "validuser", "password": "ValidPass1"}, (True, None)),
        ({"password": "ValidPass1"}, (False, "Missing required field: username")),
        ({"username": "validuser"}, (False, "Missing required field: password")),
        (
            {"username": "validuser", "password": "ValidPass1", "extra": "unexpected"},
            (False, "Unexpected fields in body"),
        ),
        ({}, (False, "Empty body")),
    ],
)
def test_login_validator(login_validator, body, expected):
    assert login_validator.validate(body) == expected

# -------------------- QueryParamsValidator Tests --------------------

@pytest.fixture
def query_params_validator():
    return QueryParamsValidator(required_params={'a', 'b'})

@pytest.mark.parametrize(
    "params, expected",
    [
        ({"a": 1, "b": 2}, (True, None)),
        ({}, (False, "Empty query parameters")),
        ({"a": 1}, (False, "Missing required query parameter: b")),
        ({"b": 2}, (False, "Missing required query parameter: a")),
        ({"a": 1, "b": 2, "c": 3}, (False, "Unexpected query parameters")),
    ],
)
def test_query_params_validator(query_params_validator, params, expected):
    assert query_params_validator.validate(params) == expected

# -------------------- ActivateValidator Tests --------------------

@pytest.fixture
def activate_validator():
    return ActivateValidator()

@pytest.mark.parametrize(
    "params, expected",
    [
        ({"username": "validuser", "token": "sometoken"}, (True, None)),
        ({"token": "sometoken"}, (False, "Missing required query parameter: username")),
        ({"username": "validuser"}, (False, "Missing required query parameter: token")),
        (
            {"username": "validuser", "token": "sometoken", "extra": "unexpected"},
            (False, "Unexpected query parameters"),
        ),
        ({}, (False, "Empty query parameters")),
    ],
)
def test_activate_validator(activate_validator, params, expected):
    assert activate_validator.validate(params) == expected
