import re
from typing import Dict, Any, Tuple
from logger import  logger


class BodyValidator:
    """ 
    Base validator for request body fields
    """
    def __init__(self, required_fields: set[str]):
        self.required_fields = required_fields

    def validate(self, body: Dict[str, Any]) -> Tuple[bool, str | None]:
        """
        Validates request body and checks if required fields are present.

        Args:
            body: Request body dictionary
        
        Returns:
            Tuple: (is_valid, error_message)
        """
        logger.info('Validating request body')
        # Check if body is empty
        if not body:
            return False, 'Empty body'

        # Check for unexpected fields
        if (set(body.keys()) - self.required_fields):
            return False, 'Unexpected fields in body'

        # Check if required fields are present
        for field in self.required_fields:
            if field not in body:
                return False, f'Missing required field: {field}'
        
        logger.info('Request body validated successfully')
        return True, None

class RegisterValidator(BodyValidator):
    """
    Validator for registration requests
    """
    def __init__(self):
        super().__init__(set(['username', 'email', 'password']))

    def validate(self, body: Dict[str, Any]) -> Tuple[bool, str | None]:
        # Validate body
        is_valid, error_message = super().validate(body)
        if not is_valid:
            return False, error_message
        
        # Validate username
        username: str = body['username']
        if not self._is_valid_username(username):
            return False, 'Username must be 8-20 characters long'
        
        # Validate email
        email: str = body['email']
        if not self._is_valid_email(email):
            return False, 'Invalid email'
        
        # Validate password
        password: str = body['password']
        if not self.is_valid_password(password):
            return False, 'Password must be 8-20 characters long'
        
        return True, None
    
    def _is_valid_username(self, username: str) -> bool:
        logger.info('Validating username')
        username_pattern = r"^(?=.{8,20}$)[-A-Za-z0-9!\"#$%&'()*+,.\/:;<=>?@\[\]\\^_`{|}~]+$"
        return bool(re.match(username_pattern, username))

    def _is_valid_email(self, email: str) -> bool:
        logger.info('Validating email')
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(email_pattern, email))

    def is_valid_password(self, password: str) -> bool:
        logger.info('Validating password')
        password_pattern = r"^(?=.{8,20}$)[-A-Za-z0-9!\"#$%&'()*+,.\/:;<=>?@\[\]\\^_`{|}~]+$"
        return bool(re.match(password_pattern, password))

class LoginValidator(BodyValidator):
    """
    Validator for login requests
    """
    def __init__(self):
        super().__init__(set(['username', 'password']))

class ResetPasswordValidator(BodyValidator):
    """
    Validator for reset password requests (/user/ PUT)
    """
    def __init__(self):
        super().__init__(set(['old_password', 'new_password']))

    def validate(self, body: Dict[str, Any]) -> Tuple[bool, str | None]:
        # Validate body
        is_valid, error_message = super().validate(body)
        if not is_valid:
            return False, error_message

        # Validate new_password
        new_password: str = body['new_password']
        if not self._is_valid_password(new_password):
            return False, 'New password must be 8-20 characters long'

        return True, None

    def _is_valid_password(self, password: str) -> bool:
        logger.info('Validating password')
        password_pattern = r"^(?=.{8,20}$)[-A-Za-z0-9!\"#$%&'()*+,.\/:;<=>?@\[\]\\^_`{|}~]+$"
        return bool(re.match(password_pattern, password))


class QueryParamsValidator:
    """
    Base validator for query parameters
    """
    def __init__(self, required_params: set[str]):
        self.required_params = required_params

    def validate(self, query_params: Dict[str, Any]) -> Tuple[bool, str | None]:
        """
        Validates query parameters and checks if required parameters are present.

        Args:
            query_params: Query parameters dictionary

        Returns:
            Tuple: (is_valid, error_message)
        """
        logger.info('Validating query parameters')
        # Check if query_params is empty
        if not query_params:
            return False, 'Empty query parameters'
        
        # Check for unexpected parameters
        if (set(query_params.keys()) - self.required_params):
            return False, 'Unexpected query parameters'

        # Check if required parameters are present
        for param in self.required_params:
            if param not in query_params:
                return False, f'Missing required query parameter: {param}'

        logger.info('Query parameters validated successfully')
        return True, None

class ActivateValidator(QueryParamsValidator):
    """
    Validator for activation requests
    """
    def __init__(self):
        super().__init__(set(['username', 'token']))

# Create validator instances
register_validator = RegisterValidator()
login_validator = LoginValidator()
reset_password_validator = ResetPasswordValidator()
activate_validator = ActivateValidator()
