import json
import traceback
from aws_lambda_typing.context import Context
from aws_lambda_typing.events import APIGatewayProxyEventV1
from response_utils import (
    error_response,
    HTTPResponse
)
from router import get_route_handler
from logger import logger


def lambda_handler(event: APIGatewayProxyEventV1, context: Context) -> HTTPResponse:
    """ Main Lambda handler function. """
    logger.info('Lambda received event: %s', json.dumps(event))

    try:
        handler = get_route_handler(event)
        if not handler:
            return error_response(404, 'Not found')
        
        logger.info('Executing handler: %s', handler.__name__)
        result = handler(event)

        logger.info('Handler result: %s', result)
        logger.info('Handler result keys: %s', result.keys())
        return result

    except Exception as e:
        logger.error('Error: %s', str(e))
        logger.error('Stack trace: %s', traceback.format_exc())
        return error_response(500, f'Internal server error: {str(e)}')
