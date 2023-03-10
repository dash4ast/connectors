import logging
import sys
import traceback
from defusedxml.ElementTree import ParseError

from flasgger import swag_from
from flask import Blueprint, request, abort, jsonify, make_response
from marshmallow import Schema, fields
from sqlalchemy.exc import IntegrityError

from connectors.db import UtilDb
from connectors.db.PostgreDbClient import PostgreDbClient
from connectors.persistence.Vulnerability import Vulnerability
from typing import Dict
from datetime import datetime
import hashlib
import defusedxml.ElementTree as Et

extract_blueprint = Blueprint('owaspzap_import', __name__)


class ExtractionSuccessResponse(Schema):
    status = fields.String(required=True, description='Service status')
    new_vulnerabilities = fields.Integer(required=True, description='total vulnerabilities')


class AuthInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class GenericInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class PostCoverityImportRequestBody(Schema):
    dash4ast_application = fields.String(required=True, description='dash4ast_application')
    report = fields.String(required=True, description='vulnerabilities in xml format')


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


@extract_blueprint.route("/owaspzap_import", methods=["POST"])
@swag_from(
    {
        'summary': 'Import vulnerabilities from Owasp ZAP',
        'description': 'Import vulnerabilities from Owasp ZAP',
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
    try:
        parsed_body = _request_body_schema.load(request.get_json())
        dash4ast_application = parsed_body['dash4ast_application']
        report = parsed_body['report']
        root = Et.fromstring(report)
        date_report = root.get("generated") #"Fri, 7 Oct 2022 13:39:43"
        date_report = date_report[5:24]
        date_report = datetime.strptime(date_report, '%d %M %Y %H:%M:%S')

    except ParseError: 
        # printing stack trace
        traceback.print_exception(*sys.exc_info())
        return _response_schema.dump({
            'status': 'error',
            'new_vulnerabilities': 0
        })

    new_vulnerabilities = 0

    db_session = PostgreDbClient().get_client()
    db_session()
    db_session.flush()

    try:
        for issue in root.find('site/alerts'):
            for location in issue.find('instances'):
                vulnerability = create_vulnerability(issue, location, dash4ast_application, date_report)
                UtilDb.add_vulnerability(db_session, vulnerability)
                new_vulnerabilities = new_vulnerabilities + 1
    except IntegrityError:
        logging.info(('IntegrityError key: ' + root))
    db_session.remove()

    # update analysis table
    analysis = UtilDb.create_analysis(dash4ast_application, 'dast', date_report)
    UtilDb.add_analysis(db_session, analysis)

    logging.info("successfully extraction")

    return _response_schema.dump({
        'status': 'ok',
        'new_vulnerabilities': new_vulnerabilities
    })


def test():
    report = open('../../../test/dast-report.xml', 'r').read()
    my_data = Et.fromstring(report)
    date_report = my_data.get("generated") #"Fri, 7 Oct 2022 13:39:43"
    print(date_report)
    date_report = date_report[5:24]
    print(date_report)
    date_report = datetime.strptime(date_report, '%d %M %Y %H:%M:%S')
    print(date_report)
    for issue in my_data.find('site/alerts'):
        for location in issue.find('instances'):
            print_vulnerability(issue, location, 'test', date_report)


def print_vulnerability(issue, location, application_name, now):
    logging.info(hashlib.sha256(get_id(issue, location).encode()).hexdigest())
    logging.info(issue.find('desc').text)
    logging.info('owaspzap')
    logging.info('dast')
    logging.info('OPEN')
    logging.info(issue.find('name').text)
    logging.info(("CWE: " + issue.find('cweid').text))
    logging.info(issue.find('confidencedesc').text.upper())
    logging.info(location.find('uri').text)
    logging.info(location.find('method').text)
    logging.info(application_name)
    logging.info(now)
    logging.info(now)
    logging.info('vulnerability')


def get_id(issue, location):
    plugin_id = str(issue.find('pluginid').text)
    param = location.find('param').text
    evidence = location.find('evidence').text
    uri = location.find('uri').text
    method = location.find('method').text

    if param is None:
        param = '-'
    if evidence is None:
        evidence = '-'

    return plugin_id + param + evidence + uri + method


def create_vulnerability(issue, location, application_name, now):
    vulnerability = Vulnerability()
    vulnerability.vulnerability_id = hashlib.sha256(get_id(issue, location).encode()).hexdigest()
    vulnerability.description = issue.find('desc').text[0:511]
    vulnerability.tool = 'owaspzap'
    vulnerability.analysis_type = 'dast'
    vulnerability.status = 'OPEN'
    vulnerability.name = issue.find('name').text
    vulnerability.tags = "CWE: " + issue.find('cweid').text
    vulnerability.severity = issue.find('confidencedesc').text.upper()
    vulnerability.component = location.find('uri').text[0:255]
    vulnerability.location = location.find('method').text
    vulnerability.application = application_name
    vulnerability.detected_date = now
    vulnerability.extraction_date = now
    vulnerability.type = 'vulnerability'
    return vulnerability


if __name__ == '__main__':
    extract()
    # test()
