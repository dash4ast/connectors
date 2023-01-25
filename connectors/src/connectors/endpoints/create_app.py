import sqlalchemy
from flasgger import swag_from
from flask import Blueprint, request, abort, jsonify, make_response
from marshmallow import Schema, fields
from sqlalchemy.exc import IntegrityError

from connectors.db import UtilDb
from connectors.db.PostgreDbClient import PostgreDbClient
from connectors.persistence.Application import Application
from typing import Dict

extract_blueprint = Blueprint('create_app', __name__)


class ExtractionSuccessResponse(Schema):
    status = fields.String(required=True, description='Service status')


class AuthInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class GenericInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class PostCoverityImportRequestBody(Schema):
    application = fields.String(required=True, description='application')
    description = fields.String(required=True, description='description')
    domain = fields.String(required=True, description='domain')
    threshold = fields.Number(required=True, description='threshold')
    business_value = fields.Number(required=True, description='business_value')


_response_schema = ExtractionSuccessResponse()
_auth_invalid_input_response_schema = AuthInvalidResponse()
_generic_invalid_input_response_schema = GenericInvalidResponse()
_request_body_schema = PostCoverityImportRequestBody()


class ExtractionInvalidInputResponse(Schema):
    messages = fields.Dict(required=True)


def _abort_due_to_invalid_input(messages: Dict) -> None:
    abort(make_response(jsonify(_auth_invalid_input_response_schema.dump({'messages': messages})), 422))


def _abort_due_to_application_not_found(messages: Dict) -> None:
    abort(make_response(jsonify(_auth_invalid_input_response_schema.dump({'messages': messages})), 404))


@extract_blueprint.route("/create_app", methods=["POST"])
@swag_from(
    {
        'summary': 'Create an application',
        'description': 'Create an application in dash4ast',
        'responses': {
            '200': {
                'description': 'Creation successfully done',
                'content': {
                    'application/json': {
                        'schema': ExtractionSuccessResponse
                    }
                }
            },
            '422': {
                'description': 'Some of the inputs are invalid',
                'content': {
                    'application/json': {
                        'schema': AuthInvalidResponse
                    }
                }
            },
            '404': {
                'description': 'Application not found',
                'content': {
                    'application/json': {
                        'schema': AuthInvalidResponse
                    }
                }
            },
            '500': {
                'description': 'Server Error',
                'content': {
                    'application/json': {
                        'schema': GenericInvalidResponse
                    }
                }
            },
        }
    }
)
def create():
    parsed_body = _request_body_schema.load(request.get_json())
    application = parsed_body['application']
    description = parsed_body['description']
    domain = parsed_body['domain']
    threshold = parsed_body['threshold']
    business_value = parsed_body['business_value']

    db_session = PostgreDbClient().get_client()
    db_session()

    # check if application already exists..
    app: Application = db_session.query(Application) \
        .filter_by(application_name=application) \
        .filter_by(domain_name=domain).first()
    if app is not None:
        return _abort_due_to_invalid_input({'messages': ['application: ' + application + ' for domain: '
                                                         + domain + ' already exists']})

    # check if application has not strange characters

    # check if threshold is between 0 and 100
    if threshold < 0 or threshold > 100:
        return _abort_due_to_invalid_input({'messages': ['threshold must be between 0 and 100']})

    # check if business value is between 0 and 10
    if business_value < 0 or business_value > 10:
        return _abort_due_to_invalid_input({'messages': ['business_value must be between 0 and 10']})

    try:
        application = create_application(application, description, domain, threshold, business_value)
        UtilDb.add_application(db_session, application)
    except IntegrityError:
        print('Error creating an application')
    db_session.remove()

    print("successfully extraction")

    return _response_schema.dump({
        'status': 'ok'
    })


def create_application(application_name, description, domain, threshold, business_value):
    application = Application()
    application.application_name = application_name
    application.description = description
    application.domain_name = domain
    application.threshold = threshold
    application.business_risk = business_value

    return application


if __name__ == '__main__':
    create()
