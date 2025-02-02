from typing import Callable, Dict, Optional, Tuple
from aws_lambda_typing.events import APIGatewayProxyEventV1
from handlers import (
    handle_register,
    handle_activate,
    handle_login,
    handle_user
)
from response_utils import HTTPResponse
from logger import logger

# Handler type definition
HandlerType = Callable[[APIGatewayProxyEventV1], HTTPResponse]

# Define routes
ROUTES: Dict[Tuple[str, str], HandlerType] = {
    ('/auth/register', 'POST'): handle_register,
    ('/auth/activate', 'GET'): handle_activate,
    ('/auth/login', 'POST'): handle_login,
    ('/auth/user', 'GET'): handle_user,
    ('/auth/user', 'DELETE'): handle_user,
    ('/auth/user', 'PUT'): handle_user
}

def get_route_handler(event: APIGatewayProxyEventV1) -> Optional[HandlerType]:
    """ Extract route information and return the appropriate handler. """
    try:
        path: str = event['path']
        method: str = event['httpMethod']
        route_info: Tuple[str, str] = (path, method)

        logger.info('Request received: %s', route_info)

        handler : Optional[HandlerType] = ROUTES.get(route_info)
        if handler:
            logger.debug('Handler found: %s', handler.__name__)
            return handler

        logger.error('No handler found for: %s', route_info)
        return None

    except KeyError as e:
        logger.error('Missing required event key: %s', str(e))

    except Exception as e:
        logger.error('Error in get_route_handler: %s', str(e))
        return None
