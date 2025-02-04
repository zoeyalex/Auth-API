import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any
import boto3
import bcrypt
import jwt
from aws_lambda_typing.events import APIGatewayProxyEventV1
from response_utils import error_response, success_response, HTTPResponse
from auth_service import get_jwt_secret, require_auth
from logger import logger
from validators import register_validator, login_validator, reset_password_validator, activate_validator


# Initialize AWS resources
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['USERS_TABLE'])
ses = boto3.client('ses')
# get email authorized with SES from template 
SENDER_EMAIL: str = os.environ['SENDER_EMAIL']
if not SENDER_EMAIL:
    logger.error('SENDER_EMAIL environment variable not set')
    raise ValueError('SENDER_EMAIL environment variable not set')

def get_api_endpoint(event: APIGatewayProxyEventV1) -> str:
    headers = event.get('headers', {})
    host = headers.get('Host', '')
    stage = event.get('requestContext', {}).get('stage', '')
    logger.info('Host: %s, Stage: %s', host, stage)
    return f'https://{host}/{stage}'

def handle_register(event: APIGatewayProxyEventV1) -> HTTPResponse:
    logger.info('Starting registration process')
    try:
        body: Dict[str, Any] = json.loads(event.get('body', '{}'))
        logger.info(f'Parsed body: {body}')

        # Validate request body
        is_valid, error_message = register_validator.validate(body)
        if not is_valid:
            logger.warning('Registration failed: %s', error_message)
            return error_response(400, error_message)

        email: str = body.get('email')
        username: str = body.get('username')
        password: str = body.get('password')
        
        # Check if user exists
        response: Dict[str, Any] = table.get_item(
            Key={
                'username': username
            }
        )
        if 'Item' in response:
            logger.warning('Registration failed: Username %s taken', username)
            return error_response(400, f'Username {username} taken')
        
        # Generate new salt and hash for password encode to bytes then decode to store in db
        salt: bytes = bcrypt.gensalt()
        hashed_password: bytes = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Generate activation token
        jwt_secret: str = get_jwt_secret()
        activation_token: str = jwt.encode(
            {
                'username': username,
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow()
            },
            jwt_secret,
            algorithm='HS256'
        )

        # Generate timestamp
        created_at: str = datetime.now().isoformat()

        # Create user with pending activation
        table.put_item(
            Item={
                'username': username,
                'email': email,
                'password': hashed_password.decode('utf-8'),
                'created_at': created_at,
                'updated_at': created_at,
                'last_login': '', # None seems to resolve into Null: True
                'is_active': False,
                'activation_token': activation_token
            }
        )

        # Generate activation link
        api_endpoint: str = get_api_endpoint(event)
        activation_link: str = f'{api_endpoint}/auth/activate?token={activation_token}&username={username}'

        # Compose and send mail to newly registered user
        email_body = f'''
        Hi {username},

        Thank you for registering! Please click the following link to activate your account: {activation_link}
        '''
        ses.send_email(
            Source=SENDER_EMAIL,
            Destination={
                'ToAddresses': [
                    email
                ]
            },
            Message={
                'Subject': {
                    'Data': 'Activate your account',
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {
                        'Data': email_body,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )

        logger.info('Registration pending for user: %s', username)
        return success_response(f'Registration pending for user: {username}')

    except Exception as e:
        logger.error('Error in handle_register: %s', str(e))
        raise

def handle_activate(event: APIGatewayProxyEventV1) -> HTTPResponse:
    logger.info('Starting activation process')
    try:
        # Get token and username from query params
        query_params: Dict[str, Any] = event.get('queryStringParameters', {})

        is_valid, error_message = activate_validator.validate(query_params)
        if not is_valid:
            logger.warning('Activation failed: %s', error_message)
            return error_response(400, error_message)
        username = query_params.get('username')
        token = query_params.get('token')

        # Get user from database
        response: Dict[str, Any] = table.get_item(
            Key={
                'username': username
            }
        )
        if 'Item' not in response:
            logger.warning('User %s not found', username)
            return error_response(404, f'User {username} not found')
        
        user = response['Item']

        # Verify token
        if user['activation_token'] != token:
            logger.warning('Invalid activation token')
            return error_response(401, 'Invalid activation token')
        if user['is_active']:
            logger.warning('User %s already activated', username)
            return error_response(400, 'User already activated')

        # Update and activate user
        table.update_item(
            Key={
                'username': username
            },
            UpdateExpression='SET is_active = :active, updated_at = :updated_at REMOVE activation_token',
            ExpressionAttributeValues={
                ':active': True,
                ':updated_at': datetime.now().isoformat()
            }
        )
        logger.info('User %s activated successfully', username)
        return success_response(f'User: {username} activated successfully')

    except Exception as e:
        logger.error('Error in handle_activate: %s', str(e))
        raise

def handle_login(event: APIGatewayProxyEventV1) -> HTTPResponse:
    logger.info('Starting login process')
    try:
        body: Dict[str, Any] = json.loads(event.get('body'))

        # Validate request body
        is_valid, error_message = login_validator.validate(body)
        if not is_valid:
            logger.warning('Login failed: %s', error_message)
            return error_response(400, error_message)

        username: str = body.get('username')
        password: str = body.get('password')

        # Get user from database
        response: Dict[str, Any] = table.get_item(
            Key={
                'username': username
            }
        )

        if 'Item' not in response:
            logger.warning('User %s not found', username)
            return error_response(401, 'Invalid credentials')
        
        # Verify password
        stored_password: bytes = response['Item']['password'].encode('utf-8')
        if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
            logger.warning('Invalid credentials for user %s', username)
            return error_response(401, 'Invalid credentials')
        
        jwt_secret: str = get_jwt_secret()
        token: str  = jwt.encode(
            {
                'username': username,
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow()
            },
            jwt_secret,
            algorithm='HS256'
        )

        # Update last login
        table.update_item(
            Key={
                'username': username
            },
            UpdateExpression='SET last_login = :last_login',
            ExpressionAttributeValues={
                ':last_login': datetime.now().isoformat()
            }
        )

        logger.info('Login successful for user %s', username)
        return success_response({'message': 'Login successul', 'token': token})
    
    except Exception as e:
        logger.error('Error in handle_login: %s', str(e))
        raise

@require_auth
def handle_user(event: APIGatewayProxyEventV1) -> HTTPResponse:
    username: str = event['requestContext']['authorizedUsername']
    method: str = event['httpMethod']

    # Get user info
    if method == 'GET':
        response: Dict[str, Any] = table.get_item(
            Key={
                'username': username
            }
        )

        logger.info('User %s info retrieved successfully', username)
        return success_response(
            {
            'username': username,
            'email': response['Item'].get('email'),
            'created_at': response['Item'].get('created_at'),
            'updated_at': response['Item'].get('updated_at'),
            'last_login': response['Item'].get('last_login'),
            'is_active': response['Item'].get('is_active')
            }
        )
    # Delete user
    elif method == 'DELETE':
        table.delete_item(
            Key={
                'username': username
            }
        )

        logger.info('User %s deleted successfully', username)
        return success_response(f'User {username} deleted successfully')
    # Reset user password
    elif method == 'PUT':
        body: Dict[str, Any] = json.loads(event.get('body'))
        logger.info(f'Parsed body: {body}')
        
        is_valid, error_message = reset_password_validator.validate(body)
        if not is_valid:
            logger.warning('Reset password failed: %s', error_message)
            return error_response(400, error_message)

        old_pasword: str = body.get('old_password')
        new_password: str = body.get('new_password')

        # Get stored password
        response: Dict[str, Any] = table.get_item(
            Key={
                'username': username
            }
        )

        # Verify old password
        stored_password: bytes = response['Item']['password'].encode('utf-8')
        if not bcrypt.checkpw(old_pasword.encode('utf-8'), stored_password):
            logger.warning('Invalid credentials for user %s', username)
            return error_response(401, 'Invalid credentials')

        # Generate new salt and hash new password
        salt: bytes = bcrypt.gensalt()
        new_hashed_password: bytes = bcrypt.hashpw(new_password.encode('utf-8'), salt)

        # Update password and updated_at
        table.update_item(
            Key={
                'username': username
            },
            UpdateExpression='SET password = :password, updated_at = :updated_at',
            ExpressionAttributeValues={
                ':password': new_hashed_password.decode('utf-8'),
                ':updated_at': datetime.now().isoformat()
            }
        )

        logger.info('Password for user %s reset successfully', username)
        return success_response(f'Password for user {username} reset successfully')
