import sqlalchemy
from blackduck import Client
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

extract_blueprint = Blueprint('blackduck_extractor', __name__)


class ExtractionSuccessResponse(Schema):
    status = fields.String(required=True, description='Service status')
    new_components = fields.Integer(required=True, description='total components')
    new_vulnerabilities = fields.Integer(required=True, description='total vulnerabilities')
    version = fields.String(required=True, description='version that was synchronized')


class AuthInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class GenericInvalidResponse(Schema):
    messages = fields.Dict(required=True)


class PostInstanceSegmentationRequestBody(Schema):
    blackduck_url = fields.String(required=True, description='blackduck_url')
    blackduck_api_key = fields.String(required=True, description='blackduck_api_key')
    blackduck_application = fields.String(required=True, description='blackduck_application')
    dash4ast_application = fields.String(required=True, description='dash4ast_application')
    analysis_type = fields.String(required=False, description='analysis type: sca or images')

_response_schema = ExtractionSuccessResponse()
_auth_invalid_input_response_schema = AuthInvalidResponse()
_generic_invalid_input_response_schema = GenericInvalidResponse()
_request_body_schema = PostInstanceSegmentationRequestBody()


class ExtractionInvalidInputResponse(Schema):
    messages = fields.Dict(required=True)


def _abort_due_to_invalid_input(messages: Dict) -> None:
    abort(make_response(jsonify(_auth_invalid_input_response_schema.dump({'messages': messages})), 401))


def _abort_due_to_application_not_found(messages: Dict) -> None:
    abort(make_response(jsonify(_auth_invalid_input_response_schema.dump({'messages': messages})), 404))


@extract_blueprint.route("/blackduck_extractor", methods=["POST"])
@swag_from(
    {
        'summary': 'Extract vulnerabilities from Blackduck',
        'description': 'Extract vulnerabilities from Blackduck',
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
    DEFAULT_BUSINESS_RISK_VALUE = 5
    DEFAULT_THRESHOLD = 75
    DEFAULT_BLACKDUCK_ANALYSIS_TYPE = 'sca'

    parsed_body = _request_body_schema.load(request.get_json())
    url_blackduck = parsed_body['blackduck_url']
    apikey = parsed_body['blackduck_api_key']
    blackduck_application = parsed_body['blackduck_application']
    dash4ast_application = parsed_body['dash4ast_application']

    if parsed_body['analysis_type'] is not None:
        analysis_type = parsed_body['analysis_type']
    else:
        analysis_type = DEFAULT_BLACKDUCK_ANALYSIS_TYPE

    new_vulnerabilities = 0
    new_components = 0
    application_found = False

    db_session = PostgreDbClient().get_client()
    db_session()
    db_session.flush()
    try:
        bd = Client(
            token=apikey,
            base_url=url_blackduck,
            # verify=False  # TLS certificate verification
        )
    except RuntimeError:
        _abort_due_to_invalid_input({'messages': ['Possibly authentication failed']})

    now = datetime.now()
    for project in bd.get_items("/api/projects"):
        application_name = project['name']
        if blackduck_application == application_name:
            application_found = True
            print("Extracting vulnerabilities for application: " + application_name)
            # Avoid duplications
            application: Application = db_session.query(Application) \
                .filter_by(application_name=dash4ast_application).first()
            if application is None:
                application = Application()
                application.application_name = dash4ast_application
                application.domain_name = 'default'
                application.description = 'write description here'
                application.business_risk = DEFAULT_BUSINESS_RISK_VALUE
                application.threshold = DEFAULT_THRESHOLD
                db_session.add(application)
                db_session.commit()
                db_session.flush()
            url_versions = project['_meta']['links'][0]['href']  # TODO: change this
            last_version = get_latest_version(bd, url_versions)
            version = last_version['versionName']
            url_components_last_version = last_version['_meta']['href'] + '/components'
            for component in bd.get_items(url_components_last_version):
                links = component['_meta']['links']
                try:
                    vuln_id = get_component_id(component, get_license_name(component['licenses']), dash4ast_application)
                    vulnerability: Vulnerability = db_session.query(Vulnerability) \
                        .filter_by(vulnerability_id=vuln_id) \
                        .filter_by(extraction_date=now).first()
                    if vulnerability is None:
                        new_components += 1
                        vulnerability = create_license_issue(component, dash4ast_application, 'license', now, vuln_id, analysis_type)
                        UtilDb.add_vulnerability(db_session, vulnerability)
                    for link in links:
                        type_link = link['rel']
                        if type_link == 'vulnerabilities':
                            url_vulnerabilities = link['href']
                            for vuln in bd.get_items(url_vulnerabilities):
                                vuln_id = get_component_id(component, vuln['name'], dash4ast_application)
                                vulnerability: Vulnerability = db_session.query(Vulnerability) \
                                    .filter_by(vulnerability_id=vuln_id) \
                                    .filter_by(extraction_date=now).first()
                                if vulnerability is None:
                                    new_vulnerabilities += 1
                                    vulnerability = create_vulnerability(component, vuln, dash4ast_application, 'vulnerability', now, vuln_id, analysis_type)
                                    UtilDb.add_vulnerability(db_session, vulnerability)
                except IntegrityError:
                    message = 'IntegrityError inserting component: ' + component['componentName']
                    _abort_due_to_invalid_input({'messages': [message]})
                except sqlalchemy.exc.InvalidRequestError:
                    message = 'InvalidRequestError inserting component: ' + component['componentName']
                    _abort_due_to_invalid_input({'messages': [message]})
    db_session.remove()

    # update analysis table
    analysis = UtilDb.create_analysis(dash4ast_application, analysis_type, now)
    UtilDb.add_analysis(db_session, analysis)

    print("successfully extraction")

    if not application_found:
        _abort_due_to_application_not_found({'messages': ['Blackduck application not found']})

    return _response_schema.dump({
        'status': 'ok',
        'new_components': new_components,
        'new_vulnerabilities': new_vulnerabilities,
        'version': version
    })


def get_component_id(component, issue_name, application_name):
    component_name = component['componentName']
    if "componentVersionName" in component:
        component_version_name = component['componentVersionName']
    else:
        component_version_name = 'unknown'
    key = hashlib.md5(
        str(issue_name + component_name + component_version_name + application_name).encode()).hexdigest()
    return key


def create_vulnerability(component, issue, application_name, vulnerability_type, extraction_date, key, analysis_type):
    vulnerability = Vulnerability()
    component_name = component['componentName']
    if "componentVersionName" in component:
        component_version_name = component['componentVersionName']
    else:
        component_version_name = 'unknown'
    vulnerability.vulnerability_id = key
    vulnerability.description = issue['description'][0:511]
    vulnerability.tool = 'blackduck'
    vulnerability.analysis_type = analysis_type
    vulnerability.name = issue['name']
    vulnerability.status = 'OPEN'
    vulnerability.severity = get_vulnerability_risk(issue)
    vulnerability.tags = str(issue['bdsaTags'])
    vulnerability.component = component_name
    vulnerability.location = component_version_name
    vulnerability.application = application_name
    vulnerability.detected_date = issue['publishedDate'][0:10]
    vulnerability.extraction_date = extraction_date
    vulnerability.type = vulnerability_type
    return vulnerability


def create_license_issue(component, application_name, vulnerability_type, extraction_date, key, analysis_type):
    vulnerability = Vulnerability()
    component_name = component['componentName']
    if "componentVersionName" in component:
        component_version_name = component['componentVersionName']
    else:
        component_version_name = 'unknown'
    vulnerability.vulnerability_id = key
    vulnerability.description = get_license_name(component['licenses'])[0:511]
    vulnerability.tool = 'blackduck'
    vulnerability.analysis_type = analysis_type
    vulnerability.name = get_license_name(component['licenses'])[0:63]
    vulnerability.status = get_status(component['approvalStatus'])
    vulnerability.severity = get_license_risk(component['licenseRiskProfile'])
    link_component = get_link_component(component['_meta']['links'])
    vulnerability.tags = link_component  # TODO: Use Match Type field instead of Usage
    vulnerability.component = component_name
    vulnerability.location = component_version_name
    vulnerability.application = application_name
    vulnerability.detected_date = component['releasedOn'][0:10]
    vulnerability.extraction_date = extraction_date
    vulnerability.type = vulnerability_type
    return vulnerability


def get_link_component(links):
    link_component = ''
    for link in links:
        type_link = link['rel']
        if type_link == "component-home":
            link_component = link['href']
    return link_component


def get_status(status):
    if status == "NOT_REVIEWED":
        status = "OPEN"
    if status == "NOT_IN_VIOLATION":
        status = "OPEN"
    return status


def get_vulnerability_risk(issue):
    if "cvss3" in issue:
        cvss3 = issue['cvss3']
        return cvss3['severity']
    if "cvss2" in issue:
        cvss2 = issue['cvss2']
        return cvss2['severity']
    return issue['severity']


def get_license_risk(component_license_risk_profile):
    counts = component_license_risk_profile['counts']
    for count in counts:
        n = count['count']
        if n > 0:
            if count['countType'] != 'OK':
                return count['countType']
    return 'INFO'


def get_license_name(licenses):
    for license_item in licenses:
        license_name = license_item['licenseDisplay']
        return license_name
    return 'Unknown'


def get_latest_version(bd, url_versions):
    last_date = '2000-01-01T00:00:00.001Z'
    for version in bd.get_items(url_versions):
        date_update_version = version['settingUpdatedAt']
        if date_update_version > last_date:
            last_date = date_update_version
            last_version = version
    return last_version


if __name__ == '__main__':
    extract()
