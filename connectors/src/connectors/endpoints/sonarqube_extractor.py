import datetime

import sonarqube
from sonarqube import SonarQubeClient
from sqlalchemy.exc import IntegrityError

from flasgger import swag_from
from flask import Blueprint, request, abort, jsonify, make_response
from marshmallow import Schema, fields
from typing import Dict
from datetime import date, datetime

from connectors.persistence.Application import Application
from connectors.db.PostgreDbClient import PostgreDbClient
from connectors.persistence.Vulnerability import Vulnerability
import hashlib

extract_blueprint = Blueprint('sonarqube_extractor', __name__)


class ExtractionSuccessResponse(Schema):
    status = fields.String(required=True, description='Service status')
    new_vulnerabilities = fields.Integer(required=True, description='total vulnerabilities synchronized')
    hot_spot_vulnerabilities = fields.Integer(required=True, description='total hot spot synchronized')


class AuthInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class GenericInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class PostInstanceSegmentationRequestBody(Schema):
    sonarqube_url = fields.String(required=True, description='sonarqube_url')
    sonarqube_user = fields.String(required=True, description='sonarqube_user')
    sonarqube_password = fields.String(required=True, description='sonarqube_password')
    dash4ast_application = fields.String(required=True, description='dash4ast_application')
    sonarqube_application = fields.String(required=True, description='sonarqube_application')


_response_schema = ExtractionSuccessResponse()
_auth_invalid_input_response_schema = AuthInvalidResponse()
_generic_invalid_input_response_schema = GenericInvalidResponse()
_request_body_schema = PostInstanceSegmentationRequestBody()


def _abort_due_to_invalid_input(messages: Dict) -> None:
    abort(make_response(jsonify(_auth_invalid_input_response_schema.dump({'messages': messages})), 401))


def _abort_due_to_application_not_found(messages: Dict) -> None:
    abort(make_response(jsonify(_auth_invalid_input_response_schema.dump({'messages': messages})), 404))


@extract_blueprint.route("/sonarqube_extractor", methods=["POST"])
@swag_from(
    {
        'summary': 'Extract vulnerabilities from Sonarqube',
        'description': 'Extract vulnerabilities from Sonarqube',
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
    url_sonar = parsed_body['sonarqube_url']
    username = parsed_body['sonarqube_user']
    password = parsed_body['sonarqube_password']
    sonarqube_application = parsed_body['sonarqube_application']
    dash4ast_application = parsed_body['dash4ast_application']

    try:
        sonar = SonarQubeClient(sonarqube_url=url_sonar, username=username, password=password)
        sonar.auth.authenticate_user(login=username, password=password)
    except sonarqube.utils.exceptions.AuthError:
        _abort_due_to_invalid_input({'messages': ['Possibly authentication failed']})

    new_vulnerabilities = 0
    hot_spot_vulnerabilities = 0
    db_session = PostgreDbClient().get_client()
    db_session()
    db_session.flush()

    projects = list(sonar.projects.search_projects())

    found_application = False

    for project in projects:

        project_key = project['key']
        application_name = project['name']

        if application_name == sonarqube_application:
            found_application = True
            print('checking application: ' + application_name)
            # Avoid duplications
            application: Application = db_session.query(Application) \
                .filter_by(application_name=dash4ast_application).first()
            if application is None:
                application = Application()
                application.application_name = dash4ast_application
                application.domain_name = 'default'
                application.description = 'write description here'
                application.business_risk = 2
                application.threshold = 70
                db_session.add(application)
                db_session.commit()
                db_session.flush()

            print("Retrieving hot_spots for project: " + application_name)
            hot_spots = list(sonar.hotspots.search_hotspots(projectKey=project_key))
            now = datetime.now()
            for hot_spot in hot_spots:
                try:
                    vulnerability = create_vulnerability(hot_spot, dash4ast_application, 'HOT_SPOT', now)
                    add_vulnerability(db_session, vulnerability)
                    hot_spot_vulnerabilities += 1
                except IntegrityError:
                    print('IntegrityError key: ' + hot_spot['key'])

            print("Retrieving vulnerabilities for project: " + project_key)
            issues = list(sonar.issues.search_issues(componentKeys=project_key))
            for issue in issues:
                vulnerability_type = issue['type']
                if vulnerability_type == 'VULNERABILITY':
                    try:
                        vulnerability = create_vulnerability(issue, dash4ast_application, vulnerability_type, now)
                        add_vulnerability(db_session, vulnerability)
                        new_vulnerabilities += 1
                    except IntegrityError:
                        print('IntegrityError key: ' + issue['key'])
    db_session.remove()
    if not found_application:
        _abort_due_to_application_not_found({'messages': ['Sonarqube application not found']})
    print("successfully extraction")
    print('new_vulnerabilities ' + str(new_vulnerabilities))
    print('hot_spot_vulnerabilities ' + str(hot_spot_vulnerabilities))
    return _response_schema.dump({
        'status': 'ok',
        'new_vulnerabilities': new_vulnerabilities,
        'hot_spot_vulnerabilities': hot_spot_vulnerabilities
    })


def update_vulnerability(db_session, status, vulnerability):
    setattr(vulnerability, 'status', status)
    db_session.commit()
    db_session.flush()


def add_vulnerability(db_session, vulnerability):
    db_session.add(vulnerability)
    db_session.commit()
    db_session.flush()


def create_vulnerability(issue, application_name, vulnerability_type, now):
    vulnerability = Vulnerability()
    vulnerability.vulnerability_id = hashlib.md5(str(issue['key']).encode()).hexdigest()
    vulnerability.description = issue['message']
    vulnerability.tool = 'sonarqube'
    vulnerability.analysis_type = 'sast'
    vulnerability.status = get_status(issue['status'])
    if vulnerability_type == 'VULNERABILITY':
        vulnerability.name = issue['rule']
        vulnerability.severity = get_severity_vulnerability(issue['severity'])
        vulnerability.tags = str(issue['tags'])
    if vulnerability_type == 'HOT_SPOT':
        vulnerability.name = issue['securityCategory']
        vulnerability.severity = get_severity_hotspot(issue['vulnerabilityProbability'])
        vulnerability.tags = vulnerability_type
    project = issue['project']
    vulnerability.component = issue['component'].replace(project + ':', "")
    if "line" in issue:
        vulnerability.location = issue['line']
    else:
        vulnerability.location = 'unknown'
    vulnerability.application = application_name
    vulnerability.detected_date = issue['creationDate'][0:10]
    vulnerability.extraction_date = now
    vulnerability.type = 'vulnerability'
    return vulnerability


def get_status(status):
    status_dash4ast = status
    if status == "TO_REVIEW":
        status_dash4ast = "OPEN"
    if status == "CONFIRMED":
        status_dash4ast = "OPEN"
    if status == "OPEN":
        status_dash4ast = "OPEN"
    return status_dash4ast


def get_severity_vulnerability(severity_sonar):
    # severity_types <- c("CRITICAL","HIGH","MEDIUM","LOW","INFO")
    severity_dash4ast = "INFO"
    if severity_sonar == "BLOCKER":
        severity_dash4ast = "CRITICAL"
    if severity_sonar == "CRITICAL":
        severity_dash4ast = "HIGH"
    if severity_sonar == "MAJOR":
        severity_dash4ast = "MEDIUM"
    if severity_sonar == "MINOR":
        severity_dash4ast = "LOW"
    if severity_sonar == "INFO":
        severity_dash4ast = "INFO"
    return severity_dash4ast


def get_severity_hotspot(severity_sonar):
    # severity_types <- c("CRITICAL","HIGH","MEDIUM","LOW","INFO")
    severity_dash4ast = "LOW"
    if severity_sonar == "HIGH":
        severity_dash4ast = "CRITICAL"
    if severity_sonar == "LOW":
        severity_dash4ast = "MEDIUM"
    return severity_dash4ast


if __name__ == '__main__':
    extract()
