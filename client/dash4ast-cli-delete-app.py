import requests
import sys


def post_request(url_dash4ast, app_name, app_domain):
    endpoint = url_dash4ast + '/' + 'delete_app'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    data = {'application': app_name, 'domain': app_domain}
    r = requests.post(endpoint, json=data, headers=headers)
    if r.status_code != 200:
        sys.exit(f'POST failed: {r.text}')
    print(r.text)


if __name__ == "__main__":

    if len(sys.argv) == 7:
        url = sys.argv[2]
        app = sys.argv[4]
        domain = sys.argv[6]
    else:
        print(
            'Usage: python3 dash4ast-cli-delete-app.py --host HOST --application APPLICATION_NAME --domain DOMAIN')
        print(
            'Example: python3 dash4ast-cli-delete-app.py --host http://localhost:5000 --application python-test-project --domain demo')
        sys.exit()

    post_request(url, app, domain)
