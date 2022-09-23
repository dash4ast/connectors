import requests


def post_request():

    url = 'http://localhost:5000/bandit_json_import'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    report = open('/home/sebas/tas/source/dash4ast/tool/connectors/test/bandit-output.json', 'r').read()
    application = 'dash4ast_connectors2'
    print(url)
    data = {'dash4ast_application': application, 'report': report}
    r = requests.post(url, json=data, headers=headers)
    print(r.text)


if __name__ == "__main__":
    post_request()
