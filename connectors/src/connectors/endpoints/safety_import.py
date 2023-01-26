import logging
from flasgger import swag_from
from flask import Blueprint, request, abort, jsonify, make_response
from marshmallow import Schema, fields
from sqlalchemy.exc import IntegrityError

from connectors.db import UtilDb
from connectors.db.PostgreDbClient import PostgreDbClient
from connectors.persistence.Application import Application
from connectors.persistence.Vulnerability import Vulnerability
from typing import Dict
from datetime import datetime
import hashlib
import json
 
extract_blueprint = Blueprint('safety_import', __name__)


class ExtractionSuccessResponse(Schema):
    status = fields.String(required=True, description='Service status')
    new_vulnerabilities = fields.Integer(required=True, description='total vulnerabilities')


class AuthInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class GenericInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class PostCoverityImportRequestBody(Schema):
    dash4ast_application = fields.String(required=True, description='dash4ast_application')
    report = fields.String(required=True, description='vulnerabilities in json format')


_response_schema = ExtractionSuccessResponse()
_auth_invalid_input_response_schema = AuthInvalidResponse()
_generic_invalid_input_response_schema = GenericInvalidResponse()
_request_body_schema = PostCoverityImportRequestBody()


class ExtractionInvalidInputResponse(Schema):
    messages = fields.Dict(required=True)


def _abort_due_to_invalid_input(messages: Dict) -> None:
    abort(make_response(jsonify(_auth_invalid_input_response_schema.dump({'messages': messages})), 401))


def _abort_due_to_application_not_found(messages: Dict) -> None:
    abort(make_response(jsonify(_auth_invalid_input_response_schema.dump({'messages': messages})), 404))


@extract_blueprint.route("/safety_import", methods=["POST"])
@swag_from(
    {
        'summary': 'Import vulnerabilities from Safety',
        'description': 'Import vulnerabilities from Safety',
        'responses': {
            '200': {
                'description': 'Extraction successfully fetched',
                'content': {
                    'application/json': {
                        'schema': ExtractionSuccessResponse
                    }
                }
            },
            '401': {
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
def extract():
    parsed_body = _request_body_schema.load(request.get_json())
    dash4ast_application = parsed_body['dash4ast_application']
    report = parsed_body['report']
    content = json.loads(report)
    now = datetime.now()

    db_session = PostgreDbClient().get_client()
    db_session()
    db_session.flush()
    try:
        for issue in content['vulnerabilities']:
            vulnerability = create_vulnerability(issue, dash4ast_application, now)
            UtilDb.add_vulnerability(db_session, vulnerability)
    except IntegrityError:
        logging.info(('IntegrityError key: ' + issue['id']))
    db_session.remove()

    new_vulnerabilities = len(content['vulnerabilities'])

    # update analysis table
    analysis = UtilDb.create_analysis(dash4ast_application, 'sca', now)
    UtilDb.add_analysis(db_session, analysis)

    return _response_schema.dump({
        'status': 'ok',
        'new_vulnerabilities': new_vulnerabilities
    })


def create_vulnerability(issue, application_name, now):
    vulnerability = Vulnerability()
    vulnerability.vulnerability_id = hashlib.md5(str(issue['vulnerability_id']).encode()).hexdigest()
    vulnerability.description = issue['advisory'][0:511]  ## TODO: No trunk
    vulnerability.tool = 'safety'
    vulnerability.analysis_type = 'sca'
    vulnerability.status = 'OPEN'
    if issue['CVE'] is None:
        vulnerability.name = issue['vulnerability_id']
    else:
        vulnerability.name = issue['CVE']
    vulnerability.tags = "more_info_url: " + issue['more_info_url']
    if issue['severity'] is None:  # TODO: Get severity from CVE
        vulnerability.severity = 'Medium'.upper()
    else:
        vulnerability.severity = issue['severity'].upper()
    vulnerability.component = issue['package_name']
    vulnerability.location = issue['analyzed_version']
    vulnerability.application = application_name
    if issue['published_date'] is None:
        vulnerability.detected_date = now
    else:
        vulnerability.detected_date = issue['published_date']
    vulnerability.extraction_date = now
    vulnerability.type = 'vulnerability'
    return vulnerability


if __name__ == '__main__':
    extract()
