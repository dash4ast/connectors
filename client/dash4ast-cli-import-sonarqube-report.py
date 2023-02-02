import requests
import sys
import logging


def post_request(url_dash4ast, app_in_sonar, app_in_dash4ast, url_sonarqube, user_sonarqube, pwd_sonarqube):
    endpoint = url_dash4ast + '/sonarqube_extractor'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    data = {'sonarqube_url': url_sonarqube, 'sonarqube_user': user_sonarqube, 'sonarqube_password': pwd_sonarqube,
            'dash4ast_application': app_in_dash4ast, 'sonarqube_application': app_in_sonar}
    r = requests.post(endpoint, json=data, headers=headers)
    if r.status_code != 200:
        sys.exit(f'POST failed: {r.text}')
    print(r.text)


if __name__ == "__main__":

    if len(sys.argv) == 13:
        url = sys.argv[2]
        application_tool = sys.argv[4]
        application_dash4ast = sys.argv[6]
        url_tool = sys.argv[8]
        user_tool = sys.argv[10]
        pwd_tool = sys.argv[12]
    else:
        logging.info(
            'Usage: python3 dash4ast-cli-import-sonarqube-report.py --host HOST --application-tool APPLICATION_NAME --application-dash4ast APPLICATION_NAME --url-tool URL --user-tool USER --pwd-tool PWD')
        logging.info(
            'Example: python3 dash4ast-cli-import-sonarqube-report.py --host http://localhost:5000 --application-tool dash4ast-connectors --application-dash4ast connectors --url-tool http://172.17.0.1:9000/ --user-tool xxxx --pwd-tool xxxx')
        sys.exit()

    post_request(url, application_tool, application_dash4ast, url_tool, user_tool, pwd_tool)
