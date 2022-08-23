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

    ## assertion

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
        print(url)
        application = sys.argv[4]
        report = sys.argv[6]
        scan = sys.argv[8]
    else:
        print('--host $HOST')
        print('--application APPLICATION_NAME')
        print('--report REPORT_FILE')
        print('--scan SCAN_TOOL')
        sys.exit()

    ## pass args
    post_request(url, application, report, scan)

    #print_request(report)
