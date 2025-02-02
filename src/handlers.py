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


# Initialize AWS resources
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['USERS_TABLE'])
ses = boto3.client('ses')
# Set email authorized with SES
SENDER_EMAIL: str ='example@domain.com'

def get_api_endpoint(event: APIGatewayProxyEventV1) -> str:
    headers = event.get('headers', {})
    host = headers.get('Host', '')
    stage = event.get('requestContext', {}).get('stage', '')
    return f'https://{host}/{stage}'

def handle_register(event: APIGatewayProxyEventV1) -> HTTPResponse:
    print('Starting registration process')
    try:
        body: Dict[str, Any] = json.loads(event.get('body', '{}'))
        print(f'Parsed body: {body}')
        email: str | None = body.get('email')
        username: str | None = body.get('username')
        password: str | None = body.get('password')

        if not any([username, password, email]):
            return error_response(400, 'Missing username or password or email')
        
        # Check if user exists
        response: Dict[str, Any] = table.get_item(
            Key={
                'username': username
            }
        )
        if 'Item' in response:
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

        return success_response(f'Registration pending for user: {username}')
    except Exception as e:
        print(f'Error in handle_register: {str(e)}')
        raise

def handle_activate(event: APIGatewayProxyEventV1) -> HTTPResponse:
    try:
        # Get token and username from query params
        query_params: Dict[str, Any] = event.get('queryStringParameters', {})
        if not query_params:
            return error_response(400, 'Missing query parameters')
        username = query_params.get('username')
        token = query_params.get('token')
        if not all([username, token]):
            return error_response(400, 'Missing username or activation token')

        # Get user from database
        response: Dict[str, Any] = table.get_item(
            Key={
                'username': username
            }
        )
        if 'Item' not in response:
            return error_response(404, f'User {username} not found')
        
        user = response['Item']

        # Verify token
        if user['activation_token'] != token:
            return error_response(401, 'Invalid activation token')
        if user['is_active']:
            return error_response(400, 'User already activated')

        # Update and activate user
        table.update_item(
            Key={
                'username': username
            },
            UpdateExpression='SET is_active = :active REMOVE activation_token',
            ExpressionAttributeValues={
                ':active': True
            }
        )
        return success_response(f'User: {username} activated successfully')
    except Exception as e:
        print(f'Error in handle_activate: {str(e)}')
        raise

def handle_login(event: APIGatewayProxyEventV1) -> HTTPResponse:
    body: Dict[str, Any] = json.loads(event.get('body'))
    username: str = body.get('username')
    password: str = body.get('password')

    # Get user from database
    response: Dict[str, Any] = table.get_item(
        Key={
            'username': username
        }
    )

    if 'Item' not in response:
        return error_response(401, 'Invalid credentials')
    
    # Verify password
    stored_password: bytes = response['Item']['password'].encode('utf-8')
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
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

    return success_response({'message': 'Login successul', 'token': token})

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

        return success_response(
            {
            'username': username,
            'email': response['Item'].get('email'),
            'created_at': response['Item'].get('created_at'),
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

        return success_response(f'User {username} deleted successfully')
    # Reset user password
    elif method == 'PUT':
        body: Dict[str, Any] = json.loads(event.get('body'))
        print(f'Parsed body: {body}')
        old_pasword: str = body.get('old_password')
        new_password: str = body.get('new_password')

        if not any([old_pasword, new_password]):
            return error_response(400, 'Missing required fields')

        # Get stored password
        response: Dict[str, Any] = table.get_item(
            Key={
                'username': username
            }
        )

        # Verify old password
        stored_password: bytes = response['Item']['password'].encode('utf-8')
        if not bcrypt.checkpw(old_pasword.encode('utf-8'), stored_password):
            return error_response(401, 'Invalid credentials')

        # Generate new salt and hash new password
        salt: bytes = bcrypt.gensalt()
        new_hashed_password: bytes = bcrypt.hashpw(new_password.encode('utf-8'), salt)

        # Update password in database
        table.update_item(
            Key={
                'username': username
            },
            UpdateExpression='set password = :p',
            ExpressionAttributeValues={
                ':p': new_hashed_password.decode('utf-8')
            }
        )

        return success_response(f'Password for user {username} reset successfully')
