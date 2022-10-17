import requests
import sys


def post_request(url_dash4ast, app_name, app_description, app_domain, app_threshold, app_business_value):
    endpoint = url_dash4ast + '/' + 'create_app'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    data = {'application': app_name, 'description': app_description, 'domain': app_domain, 'threshold': app_threshold, 'business_value': app_business_value}
    r = requests.post(endpoint, json=data, headers=headers)
    if r.status_code != 200:
        sys.exit(f'POST failed: {r.text}')
    print(r.text)


if __name__ == "__main__":

    if len(sys.argv) == 13:
        url = sys.argv[2]
        app = sys.argv[4]
        description = sys.argv[6]
        domain = sys.argv[8]
        threshold = sys.argv[10]
        business_value = sys.argv[12]
    else:
        print(
            'Usage: python3 dash4ast-cli-create-app.py --host HOST --application APPLICATION_NAME --description DESC --domain DOMAIN --threshold THRESHOLD --business_value BUSINESS_VALUE')
        print(
            'Example: python3 dash4ast-cli-create-app.py --host http://localhost:5000 --application python-test-project --description "My first python app" --domain demo --threshold 75 --business_value 7')
        sys.exit()

    post_request(url, app, description, domain, threshold, business_value)
