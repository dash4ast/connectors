from flask import Flask
from flasgger import Swagger
from flask_cors import CORS
import logging

import connectors.endpoints.sonarqube_extractor
import connectors.endpoints.blackduck_extractor
import connectors.endpoints.coverity_json_import
import connectors.endpoints.bandit_json_import
import connectors.endpoints.safety_json_import
import connectors.endpoints.checkov_json_import
import connectors.endpoints.owaspzap_xml_import
import connectors.endpoints.health

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(threadName)-10s - %(message)s')
sqla_logger = logging.getLogger('sqlalchemy')
sqla_logger.setLevel(logging.ERROR)
sqla_logger.propagate = False
for hdlr in sqla_logger.handlers:
    sqla_logger.removeHandler(hdlr)

# Flask instance
app = Flask(__name__)
app.register_blueprint(connectors.endpoints.sonarqube_extractor.extract_blueprint)
app.register_blueprint(connectors.endpoints.blackduck_extractor.extract_blueprint)
app.register_blueprint(connectors.endpoints.coverity_json_import.extract_blueprint)
app.register_blueprint(connectors.endpoints.bandit_json_import.extract_blueprint)
app.register_blueprint(connectors.endpoints.checkov_json_import.extract_blueprint)
app.register_blueprint(connectors.endpoints.safety_json_import.extract_blueprint)
app.register_blueprint(connectors.endpoints.owaspzap_xml_import.extract_blueprint)
app.register_blueprint(connectors.endpoints.health.health_blueprint)

# CORS config
CORS(app)

# Swagger config
app.config['SWAGGER'] = {
    'title': 'Extract Vulnerabilities from Security tools',
    'openapi': '3.0.2',
    'version': '1.0.0'
}
Swagger(app)
