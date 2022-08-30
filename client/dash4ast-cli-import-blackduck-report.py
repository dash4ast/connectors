import requests
import sys


def post_request(url, application_tool, application_dash4ast, url_tool, api_key_tool):

    endpoint = url + '/blackduck_extractor'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    data = {'blackduck_url': url_tool, 'blackduck_api_key': api_key_tool, 
    'dash4ast_application': application_dash4ast, 'blackduck_application': application_tool}
    r = requests.post(endpoint, json=data, headers=headers)

    print(r.text)


if __name__ == "__main__":

    if len(sys.argv) == 11:
        url = sys.argv[2]
        application_tool = sys.argv[4]
        application_dash4ast = sys.argv[6]
        url_tool = sys.argv[8]
        api_key_tool = sys.argv[10]
    else:
        print('Usage: python3 dash4ast-cli-extract-blackduck.py --host HOST --application-tool APPLICATION_NAME --application-dash4ast APPLICATION_NAME --url-tool URL --user-tool USER --pwd-tool PWD')
        print('Example: python3 dash4ast-cli-extract-blackduck.py --host http://localhost:5000 --application-tool dash4ast-connectors --application-dash4ast connectors --url-tool https://xxxx.blackduck.com --api-key-tool xxxx')
        sys.exit()

    post_request(url, application_tool, application_dash4ast, url_tool, api_key_tool)
