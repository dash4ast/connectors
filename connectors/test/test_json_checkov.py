import requests
import json
import hashlib


def post_request():

    url = 'http://localhost:5000/checkov_json_import'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    report = open('/home/sebas/tas/source/dash4ast/tool/connectors/test/checkov-output.json', 'r').read()
    application = 'dash4ast_global'
    print(url)
    data = {'dash4ast_application': application, 'report': report}
    r = requests.post(url, json=data, headers=headers)
    print(r.text)


def parse_report():
    print('checkov report')
    report = open('checkov-output.json', 'r').read()
    content = json.loads(report)
    for check_types in content:
        for issue in check_types['results']['failed_checks']:
            if issue['check_result']['result'] == 'FAILED':
                print(hashlib.md5(str(issue['check_id']).encode()).hexdigest())
                print(issue['check_id'])
                print(issue['check_name'])
                print(issue['file_abs_path'])
                print(issue['file_line_range'])
                print(issue['guideline'])
                if issue['severity'] is None:
                    print('MEDIUM')


if __name__ == "__main__":
    ## post_request()
    parse_report()


