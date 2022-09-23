from flasgger import swag_from
from flask import Blueprint
from marshmallow import Schema, fields

health_blueprint = Blueprint('health', __name__)


class HealthSuccessResponse(Schema):
    status = fields.String(required=True, description='Service status. Its value will always be \'OK\'')


_response_schema = HealthSuccessResponse()


@health_blueprint.route("/health", methods=["GET"])
@swag_from(
    {
        'summary': 'Heartbeat',
        'description': 'Checks whether the service is healthy',
        'responses': {
            '200': {
                'description': 'Service looks healthy',
                'content': {
                    'application/json': {
                        'schema': HealthSuccessResponse
                    }
                }
            }
        }
    }
)
def health():
    return _response_schema.dump({
        'status': 'OK'
    })
