import sqlalchemy
from flasgger import swag_from
from flask import Blueprint, request, abort, jsonify, make_response
from marshmallow import Schema, fields
from psycopg2 import OperationalError
from sqlalchemy.exc import IntegrityError

from connectors.db import UtilDb
from connectors.db.PostgreDbClient import PostgreDbClient
from connectors.persistence.Application import Application
from connectors.persistence.Vulnerability import Vulnerability
from typing import Dict
from datetime import datetime
import hashlib
import json

extract_blueprint = Blueprint('coverity_import', __name__)


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


@extract_blueprint.route("/coverity_import", methods=["POST"])
@swag_from(
    {
        'summary': 'Import vulnerabilities from Coverity',
        'description': 'Import vulnerabilities from Coverity',
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
        for issue in content['issues']:
            vulnerability = create_vulnerability(issue, dash4ast_application, now)
            UtilDb.add_vulnerability(db_session, vulnerability)
    except IntegrityError:
        print('IntegrityError key: ' + issue['mergeKey'])
    db_session.remove()

    new_vulnerabilities = len(content['issues'])

    # update analysis table
    analysis = UtilDb.create_analysis(dash4ast_application, 'sast', now)
    UtilDb.add_analysis(db_session, analysis)

    print("successfully extraction")

    return _response_schema.dump({
        'status': 'ok',
        'new_vulnerabilities': new_vulnerabilities
    })


def extract_test():

    report = open('../../../test/coverity-report.json', 'r').read()
    content = json.loads(report)

    dash4ast_application = 'sg-nms-be'
    now = datetime.now()

    db_session = PostgreDbClient().get_client()
    db_session()
    db_session.flush()
    try:
        for issue in content['issues']:
            print(issue['mergeKey'])
            vulnerability = create_vulnerability(issue, dash4ast_application, now)
            UtilDb.add_vulnerability(db_session, vulnerability)
    except IntegrityError:
        print('IntegrityError key: ' + issue['mergeKey'])
    except OperationalError:
        print('OperationalError key: ' + issue['mergeKey'])
    db_session.remove()

    # update analysis table
    analysis = UtilDb.create_analysis(dash4ast_application, 'sast', now)
    UtilDb.add_analysis(db_session, analysis)

    print("successfully extraction")


def create_vulnerability(issue, application_name, now):
    vulnerability = Vulnerability()
    vulnerability.vulnerability_id = hashlib.md5(str(issue['mergeKey'] + issue['strippedMainEventFilePathname'] +
                                                     str(issue['mainEventLineNumber']) +
                                                     str(issue['occurrenceNumberInMK'])).encode()).hexdigest()
    vulnerability.description = issue['checkerProperties']['subcategoryShortDescription']
    vulnerability.tool = 'coverity'
    vulnerability.analysis_type = 'sast'
    vulnerability.status = 'OPEN'
    vulnerability.name = issue['checkerName']
    vulnerability.severity = issue['checkerProperties']['impact'].upper()
    vulnerability.tags = "CWE: " + str(issue['checkerProperties']['cweCategory'])
    vulnerability.component = issue['strippedMainEventFilePathname']
    vulnerability.location = issue['mainEventLineNumber']
    vulnerability.application = application_name
    vulnerability.detected_date = now
    vulnerability.extraction_date = now
    vulnerability.type = 'vulnerability'
    return vulnerability


def test():
    report = open('../../../test/coverity-report.json', 'r').read()
    content = json.loads(report)
    print(len(content['issues']))
    now = datetime.now()
    counter = 0
    for issue in content['issues']:
        counter = counter + 1
        print('----------------------')
        print(counter)
        print_vulnerability(issue, 'test-app', now)


def print_vulnerability(issue, application_name, now):
    vulnerability = Vulnerability()
    print(hashlib.md5(str(issue['mergeKey'] + issue['strippedMainEventFilePathname'] +
                                                     str(issue['mainEventLineNumber']) +
                                                     str(issue['occurrenceNumberInMK'])).encode()).hexdigest())
    print(issue['checkerProperties']['subcategoryShortDescription'])
    print('coverity')
    print('sast')
    print('OPEN')
    print(issue['checkerName'])
    print(issue['checkerProperties']['impact'].upper())
    print("CWE: " + str(issue['checkerProperties']['cweCategory']))
    print(issue['strippedMainEventFilePathname'])
    print(issue['mainEventLineNumber'])
    print(application_name)
    print(now)
    print(now)
    print('vulnerability')
    print(hashlib.md5(str(issue['mergeKey']).encode()).hexdigest())
    print(issue['checkerProperties']['subcategoryShortDescription'])
    print(issue['checkerName'])
    print(issue['checkerProperties']['impact'].upper())
    print("CWE: " + str(issue['checkerProperties']['cweCategory']))
    print(issue['strippedMainEventFilePathname'])
    print(issue['mainEventLineNumber'])
    return vulnerability


if __name__ == '__main__':
    extract()
    # extract_test()
    # test()
