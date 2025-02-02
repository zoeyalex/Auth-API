import json
from typing import Any, TypedDict, Union


class HTTPResponse(TypedDict):
    statusCode: int
    body: Union[str, Any]

def create_response(status_code: int, body: Any) -> HTTPResponse:
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
        },
        'body': json.dumps(body),
    }

def error_response(status_code: int, message: str) -> HTTPResponse:
    return create_response(status_code, {'error': message})

def success_response(message: Any) -> HTTPResponse:
    return create_response(200, message)
