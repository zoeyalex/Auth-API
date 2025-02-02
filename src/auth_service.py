import os
import json
from typing import Dict, Any, Callable
from functools import wraps
import jwt
import boto3
from aws_lambda_typing.events import APIGatewayProxyEventV1
from response_utils import HTTPResponse, error_response
from logger import logger


secrets_client = boto3.client('secretsmanager')

def get_jwt_secret() -> str:
    secret_name: str = os.environ['JWT_SECRET_NAME']
    try:
        response: Dict[str, Any] = secrets_client.get_secret_value(SecretId=secret_name)
        secret: str = json.loads(response['SecretString'])['secret']

        logger.info('JWT secret retrieved successfully')
        return secret
    except Exception as e:
        logger.error('Error retrieving JWT secret: %s', str(e))
        raise Exception(f'Error retrieving JWT secret: {str(e)}')

def verify_token(token: str) -> str:
    try:
        jwt_secret: str = get_jwt_secret()
        payload: Dict[str, Any] = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        logger.warning('Token has expired')
        raise Exception('Token has expired')
    except jwt.InvalidTokenError:
        logger.warning('Invalid token')
        raise Exception('Invalid token')

def require_auth(handler: Callable[[APIGatewayProxyEventV1], HTTPResponse]) -> Callable[[APIGatewayProxyEventV1], HTTPResponse]:
    @wraps(handler)
    def wrapper(event: APIGatewayProxyEventV1) -> HTTPResponse:
        try:
            auth_header: str | None = event.get('headers', {}).get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                logger.warning('Missing or invalid token')
                return error_response(401, 'Missing or invalid token')
            
            token: str = auth_header.split(' ')[1]
            username: str = verify_token(token)

            if not username:
                logger.warning('Invalid or expired token')
                return error_response(401, 'Invalid or expired token')
            
            # Add authorized username to event for handler to use
            if 'requestContext' not in event:
                event['requestContext'] = {}
            event['requestContext']['authorizedUsername'] = username
            logger.info('Token verified successfully for user %s', username)
            return handler(event)

        except Exception as e:
            logger.error('Error in wrapper: %s', str(e))
            return error_response(401, 'Unauthorized')

    return wrapper
