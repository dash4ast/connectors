import sqlalchemy
from flasgger import swag_from
from flask import Blueprint, request, abort, jsonify, make_response
from marshmallow import Schema, fields
from sqlalchemy.exc import IntegrityError

from connectors.db import UtilDb
from connectors.db.PostgreDbClient import PostgreDbClient
from connectors.persistence.Application import Application
from connectors.persistence.Analysis import Analysis
from connectors.persistence.Vulnerability import Vulnerability
from typing import Dict

extract_blueprint = Blueprint('delete_app', __name__)
 

class ExtractionSuccessResponse(Schema):
    status = fields.String(required=True, description='Service status')


class AuthInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class GenericInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class PostCoverityImportRequestBody(Schema):
    application = fields.String(required=True, description='application')
    domain = fields.String(required=True, description='domain')


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


@extract_blueprint.route("/delete_app", methods=["POST"])
@swag_from(
    {
        'summary': 'Delete an application',
        'description': 'Delete an application in dash4ast',
        'responses': {
            '200': {
                'description': 'Deletion successfully done',
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
def delete():
    parsed_body = _request_body_schema.load(request.get_json())
    application = parsed_body['application']
    domain = parsed_body['domain']

    db_session = PostgreDbClient().get_client()
    db_session()

    # check if application exists...
    app: Application = db_session.query(Application) \
        .filter_by(application_name=application) \
        .filter_by(domain_name=domain).first()
    if app is None:
        return _abort_due_to_application_not_found({'messages': ['application ' + application + ' does not exist']})

    try:
        analysis_list: Analysis = db_session.query(Analysis) \
            .filter_by(application=application)
        vulnerability_list: Vulnerability = db_session.query(Vulnerability) \
            .filter_by(application=application)
        if vulnerability_list is not None:
            for vulnerability in vulnerability_list:
                UtilDb.delete_vulnerability(db_session, vulnerability)
        if analysis_list is not None:
            for analysis in analysis_list:
                UtilDb.delete_analysis(db_session, analysis)
        UtilDb.delete_application(db_session, app)
    except IntegrityError:
        print('Error deleting an application')
    db_session.remove()

    print("successfully deletion")

    return _response_schema.dump({
        'status': 'ok'
    })


def test():
    app_name = 'hola'
    dom_name = 'demo'
    db_session = PostgreDbClient().get_client()
    db_session()
    db_session.flush()
    app: Application = db_session.query(Application) \
        .filter_by(application_name=app_name) \
        .filter_by(domain_name=dom_name).first()
    if app is not None:
        UtilDb.delete_application(db_session, app)
        analysis_list: Analysis = db_session.query(Analysis) \
            .filter_by(application=app_name)
        vulnerability_list: Vulnerability = db_session.query(Vulnerability) \
            .filter_by(application=app_name)
        if analysis_list is not None:
            for analysis in analysis_list:
                UtilDb.delete_analysis(db_session, analysis)
        if vulnerability_list is not None:
            for vulnerability in vulnerability_list:
                UtilDb.delete_vulnerability(db_session, vulnerability)


if __name__ == '__main__':
    delete()
    # test()

