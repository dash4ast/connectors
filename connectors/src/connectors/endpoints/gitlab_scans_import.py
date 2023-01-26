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

extract_blueprint = Blueprint('gitlab_scans_import', __name__)


class ExtractionSuccessResponse(Schema):
    status = fields.String(required=True, description='Service status')
    new_vulnerabilities = fields.Integer(required=True, description='total vulnerabilities')


class AuthInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class GenericInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class PostImportRequestBody(Schema):
    dash4ast_application = fields.String(required=True, description='dash4ast_application')
    report = fields.String(required=True, description='vulnerabilities in json format')


_response_schema = ExtractionSuccessResponse()
_auth_invalid_input_response_schema = AuthInvalidResponse()
_generic_invalid_input_response_schema = GenericInvalidResponse()
_request_body_schema = PostImportRequestBody()


class ExtractionInvalidInputResponse(Schema):
    messages = fields.Dict(required=True)


def _abort_due_to_invalid_input(messages: Dict) -> None:
    abort(make_response(jsonify(_auth_invalid_input_response_schema.dump({'messages': messages})), 401))


def _abort_due_to_application_not_found(messages: Dict) -> None:
    abort(make_response(jsonify(_auth_invalid_input_response_schema.dump({'messages': messages})), 404))


@extract_blueprint.route("/gitlab_scans_import", methods=["POST"])
@swag_from(
    {
        'summary': 'Import vulnerabilities from Gitlab-Scans',
        'description': 'Import vulnerabilities from Gitlab-Scans',
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

    # update analysis table
    logging.info("Insert new analysis")
    analysis = UtilDb.create_analysis(dash4ast_application, 'sast', now)
    UtilDb.add_analysis(db_session, analysis)

    detected_date = content['scan']['start_time']
    for issue in content['vulnerabilities']:
        try:
            vulnerability = create_vulnerability(issue, dash4ast_application, detected_date, now)
            logging.info(("Inserting vulnerability: " + vulnerability.vulnerability_id))
            UtilDb.add_vulnerability(db_session, vulnerability)
        except IntegrityError:
            logging.info(('IntegrityError key: ' + issue['id']))
            db_session.rollback()
    db_session.remove()

    new_vulnerabilities = len(content['vulnerabilities'])

    logging.info("successfully extraction")

    return _response_schema.dump({
        'status': 'ok',
        'new_vulnerabilities': new_vulnerabilities
    })


def create_vulnerability(issue, application_name, detected_date, extracted_date):
    vulnerability = Vulnerability()
    vulnerability.vulnerability_id = hashlib.md5(str(issue['id']).encode()).hexdigest()
    vulnerability.name = issue['message']
    vulnerability.description = issue['description']
    vulnerability.tool = issue['scanner']['id']
    vulnerability.analysis_type = 'sast'
    vulnerability.status = 'OPEN'
    if issue['cve'] is not None:
        vulnerability.tags = "cve: " + issue['cve']
    vulnerability.component = issue['location']['file']
    vulnerability.location = issue['location']['start_line']
    vulnerability.severity = issue['severity'].upper()
    vulnerability.application = application_name
    vulnerability.detected_date = detected_date
    vulnerability.extraction_date = extracted_date
    vulnerability.type = 'vulnerability'
    return vulnerability


def test():
    report = open('../../../test/gl-semgrep-sast-report.json', 'r').read()
    content = json.loads(report)
    logging.info(len(content['vulnerabilities']))
    now = datetime.now()
    detected_date = content['scan']['start_time']
    counter = 0
    for issue in content['vulnerabilities']:
        counter = counter + 1
        logging.info('----------------------')
        logging.info(counter)
        print_vulnerability(issue, 'test-app', detected_date, now)


def print_vulnerability(issue, application_name, detected_date, extracted_date):
    logging.info(hashlib.md5(str(issue['id']).encode()).hexdigest())
    logging.info(issue['description'])
    logging.info(issue['scanner']['id'])
    logging.info('sast')
    logging.info('OPEN')
    logging.info(issue['message'])
    logging.info(issue['severity'].upper())
    if issue['cve'] is not None:
        logging.info(("CVE: " + str(issue['cve'])))
    logging.info(issue['location']['file'])
    logging.info(issue['location']['start_line'])
    logging.info(application_name)
    logging.info(detected_date)
    logging.info(extracted_date)


if __name__ == '__main__':
    #extract()
    test()
