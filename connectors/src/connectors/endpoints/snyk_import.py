import logging
import sqlalchemy
from flasgger import swag_from
from flask import Blueprint, request, abort, jsonify, make_response
from marshmallow import Schema, fields
from sqlalchemy.exc import IntegrityError

from connectors.db import UtilDb
from connectors.db.PostgreDbClient import PostgreDbClient
from connectors.persistence.Vulnerability import Vulnerability
from connectors.util import utilities
from typing import Dict
from datetime import datetime
import hashlib
import json 

extract_blueprint = Blueprint('snyk_import', __name__)


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


@extract_blueprint.route("/snyk_import", methods=["POST"])
@swag_from(
    {
        'summary': 'Import vulnerabilities from Snyk',
        'description': 'Import vulnerabilities from Snyk',
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
    if utilities.verify_size(report) == False:
        logging.info(('Report is too big'))
        return _auth_invalid_input_response_schema.dump({})
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

    # update analysis table
    analysis = UtilDb.create_analysis(dash4ast_application, 'sca', now)
    UtilDb.add_analysis(db_session, analysis)

    new_vulnerabilities = len(content['vulnerabilities'])

    logging.info("successfully extraction")

    return _response_schema.dump({
        'status': 'ok',
        'new_vulnerabilities': new_vulnerabilities
    })


def create_vulnerability(issue, application_name, now):
    vulnerability = Vulnerability()
    vulnerability.vulnerability_id = hashlib.sha256(str(issue['id']).encode()).hexdigest()
    vulnerability.description = issue['title']
    vulnerability.tool = 'snyk'
    vulnerability.analysis_type = 'sca'
    vulnerability.status = 'OPEN'
    vulnerability.name = issue['identifiers']['CVE']
    vulnerability.tags = "CWE: " + issue['identifiers']['CWE']
    vulnerability.severity = issue['severity'].upper()
    vulnerability.component = issue['name']
    vulnerability.location = issue['version']
    vulnerability.application = application_name
    vulnerability.detected_date = issue['publicationTime']
    vulnerability.extraction_date = now
    vulnerability.type = 'vulnerability'
    return vulnerability


if __name__ == '__main__':
    extract()

