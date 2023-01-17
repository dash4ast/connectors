import sqlalchemy
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
import xml.etree.ElementTree as ET

extract_blueprint = Blueprint('hclscan_import', __name__)


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


@extract_blueprint.route("/hclscan_import", methods=["POST"])
@swag_from(
    {
        'summary': 'Import vulnerabilities from HCL Scan',
        'description': 'Import vulnerabilities from HCL Scan',
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
    root = ET.fromstring(report)
    now = datetime.now()
    new_vulnerabilities = 0

    db_session = PostgreDbClient().get_client()
    db_session()
    db_session.flush()
    try:
        for issue_group in root.iter('issue-group'):
            for issue in issue_group:
                vulnerability = create_vulnerability(issue, dash4ast_application, now)
                UtilDb.add_vulnerability(db_session, vulnerability)
                new_vulnerabilities = new_vulnerabilities + 1
    except IntegrityError:
        print('IntegrityError key: ' + issue['id'])
    db_session.remove()

    # update analysis table
    analysis = UtilDb.create_analysis(dash4ast_application, 'sast', now)
    UtilDb.add_analysis(db_session, analysis)

    print("successfully extraction")

    return _response_schema.dump({
        'status': 'ok',
        'new_vulnerabilities': new_vulnerabilities
    })


def test():
    report = open('../../../test/hclscan-report.xml', 'r').read()
    root = ET.fromstring(report)
    now = datetime.now()
    print(root)
    for issue_group in root.iter('issue-group'):
        for issue in issue_group:
            print_vulnerability(issue, 'test', now)


def print_vulnerability(issue, application_name, now):
    print(issue.find('asoc-issue-id').text)
    print('hclscan')
    print(issue.find('issue-type/ref').text)
    print(issue.find('technology').text.lower())
    print('OPEN')
    print(issue.find('severity').text)
    print("CWE: " + issue.find('cwe/ref').text)
    print(issue.find('source-file').text)
    print(issue.find('line').text)
    print(application_name)
    print(now)
    print(now)
    print('vulnerability')


def create_vulnerability(issue, application_name, now):
    vulnerability = Vulnerability()
    vulnerability.vulnerability_id = hashlib.md5(issue.find('asoc-issue-id').text.encode()).hexdigest()
    vulnerability.description = issue.find('issue-type/ref').text
    vulnerability.tool = 'hclscan'
    vulnerability.analysis_type = issue.find('technology').text.lower()
    vulnerability.status = 'OPEN'
    vulnerability.name = issue.find('issue-type/ref').text
    vulnerability.tags = "CWE: " + issue.find('cwe/ref').text
    vulnerability.severity = issue.find('severity').text
    vulnerability.component = issue.find('source-file').text
    vulnerability.location = issue.find('line').text
    vulnerability.application = application_name
    vulnerability.detected_date = now
    vulnerability.extraction_date = now
    vulnerability.type = 'vulnerability'
    return vulnerability


if __name__ == '__main__':
    extract()
    # test()
