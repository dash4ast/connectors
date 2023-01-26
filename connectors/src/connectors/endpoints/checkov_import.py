import logging
import sqlalchemy
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

extract_blueprint = Blueprint('checkov_import', __name__)


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


@extract_blueprint.route("/checkov_import", methods=["POST"])
@swag_from(
    {
        'summary': 'Import vulnerabilities from Checkov',
        'description': 'Import vulnerabilities from Checkov',
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
    new_vulnerabilities = 0

    try:
        for check_types in content:
            for issue in check_types['results']['failed_checks']:
                if issue['check_result']['result'] == 'FAILED':
                    vulnerability = create_vulnerability(issue, dash4ast_application, now)
                    UtilDb.add_vulnerability(db_session, vulnerability)
                    new_vulnerabilities = new_vulnerabilities + 1
    except IntegrityError:
        logging.info(('IntegrityError key: ' + issue['check_id']))
    db_session.remove()

    # update analysis table
    analysis = UtilDb.create_analysis(dash4ast_application, 'iac', now)
    UtilDb.add_analysis(db_session, analysis)

    logging.info("successfully extraction")

    return _response_schema.dump({
        'status': 'ok',
        'new_vulnerabilities': new_vulnerabilities
    })


def create_vulnerability(issue, application_name, now):
    vulnerability = Vulnerability()
    vulnerability.vulnerability_id = hashlib.md5(str(issue['check_id']+issue['file_abs_path']).encode()).hexdigest()
    vulnerability.description = issue['check_name']
    vulnerability.tool = 'checkov'
    vulnerability.analysis_type = 'iac'
    vulnerability.status = 'OPEN'
    vulnerability.name = issue['check_id']
    if issue['guideline'] is None:
        vulnerability.tags = "guideline: ----"
    else:
        vulnerability.tags = "guideline: " + issue['guideline']
    if issue['severity'] is None:
        vulnerability.severity = 'MEDIUM'
    else:
        vulnerability.severity = issue['severity'].upper()
    vulnerability.component = issue['file_abs_path']
    vulnerability.location = issue['file_line_range']
    vulnerability.application = application_name
    vulnerability.detected_date = now
    vulnerability.extraction_date = now
    vulnerability.type = 'vulnerability'
    return vulnerability


if __name__ == '__main__':
    extract()
