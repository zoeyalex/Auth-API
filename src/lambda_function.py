import json
from typing import Callable, Dict, Tuple, Optional
from aws_lambda_typing.context import Context
from aws_lambda_typing.events import APIGatewayProxyEventV1
from response_utils import (
    error_response,
    HTTPResponse
)
from handlers import (
    handle_register,
    handle_activate,
    handle_login,
    handle_user
)


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

def lambda_handler(event: APIGatewayProxyEventV1, context: Context) -> HTTPResponse:
    print('Received event:', json.dumps(event))
    try:
        path: str = event['path']
        method: str = event['httpMethod']
        route_key: Tuple[str, str] = (path, method)
        print(f'Route key: {route_key}')
        handler: Optional[HandlerType] = ROUTES.get(route_key)
        print(f'Handler: {handler}')

        if not handler:
            return error_response(404, 'Not found')
        
        print('About to execute handler')
        try:
            result = handler(event)
            print(f'Handler result: {result}')
            return result
        except Exception as e:
            print(f'Error in handler execution: {str(e)}')
            raise
    except Exception as e:
        print(f'Error: {str(e)}')
        import traceback
        print(traceback.format_exc())  # Add this for stack trace
        return error_response(500, f'Internal server error: {str(e)}')
