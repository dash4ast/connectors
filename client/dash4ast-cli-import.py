import requests
import json
import sys
import hashlib


def post_request(url, app, path_report, scan):

    endpoint = url + '/' + scan + '_json_import'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    report = open(path_report, 'r').read()

    data = {'dash4ast_application': app, 'report': report}
    r = requests.post(endpoint, json=data, headers=headers)
    print(r.text)


def print_request(path_report):
    report = open(path_report, 'r').read()
    content = json.loads(report)
    for issue in content['results']:
        print_vulnerability(issue)


def print_vulnerability(issue):
    print(str(issue['test_id']))
    print(hashlib.md5(str(issue['test_id']+issue['filename']+str(issue['line_number'])).encode()).hexdigest())
    print(issue['issue_text'])
    print(issue['test_name'])
    print(issue['issue_severity'].upper())
    print(issue['filename'])
    print(issue['line_number'])


if __name__ == "__main__":

    if len(sys.argv) == 9:
        url = sys.argv[2]
        application = sys.argv[4]
        report = sys.argv[6]
        scan = sys.argv[8]
    else:
        print('Usage: python3 dash4ast-cli-import.py --host HOST --application APPLICATION_NAME --report REPORT_FILE --scan SCAN_TOOL')
        print('Example: python3 dash4ast-cli-import.py --host http://localhost:5000 --application python-test-project --report examples/test_projects/bandit-output.json --scan bandit')
        print('Example: python3 dash4ast-cli-import.py --host http://localhost:5000 --application java-test-project --report examples/test_projects/coverity-report.json --scan coverity')
        sys.exit()

    ## pass args
    post_request(url, application, report, scan)

    #print_request(report)
