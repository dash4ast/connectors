import requests
import json
import sys
import hashlib


def post_request(url, application_tool, application_dash4ast, url_tool, user_tool, pwd_tool):

    endpoint = url + '/sonarqube_extractor'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    data = {'sonarqube_url': url_tool, 'sonarqube_user': user_tool, 'sonarqube_password': pwd_tool, 
    'dash4ast_application': application_dash4ast, 'sonarqube_application': application_tool}
    r = requests.post(endpoint, json=data, headers=headers)
    
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
        print('Usage: python3 dash4ast-cli-extract-sonarqube.py --host HOST --application-tool APPLICATION_NAME --application-dash4ast APPLICATION_NAME --url-tool URL --user-tool USER --pwd-tool PWD')
        print('Example: python3 dash4ast-cli-extract-sonarqube.py --host http://localhost:5000 --application-tool dash4ast-connectors --application-dash4ast connectors --url-tool http://172.17.0.1:9000/ --user-tool xxxx --pwd-tool xxxx')
        sys.exit()

    ## pass args
    post_request(url, application_tool, application_dash4ast, url_tool, user_tool, pwd_tool)

    #print_request(report)
