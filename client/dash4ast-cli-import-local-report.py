import requests
import sys


def post_request(url_dash4ast, app_name, path_report, scan_tool):
    endpoint = url_dash4ast + '/' + scan_tool + '_json_import'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    report_content = open(path_report, 'r').read()

    data = {'dash4ast_application': app_name, 'report': report_content}
    r = requests.post(endpoint, json=data, headers=headers)
    if r.status_code != 200:
        sys.exit(f'POST failed: {r.text}')
    print(r.text)


if __name__ == "__main__":

    if len(sys.argv) == 9:
        url = sys.argv[2]
        app = sys.argv[4]
        report = sys.argv[6]
        scan = sys.argv[8]
    else:
        print(
            'Usage: python3 dash4ast-cli-import-local-report.py --host HOST --application APPLICATION_NAME --report REPORT_FILE --scan SCAN_TOOL')
        print(
            'Example: python3 dash4ast-cli-import-local-report --host http://localhost:5000 --application python-test-project --report examples/test_projects/bandit-output.json --scan bandit')
        print(
            'Example: python3 dash4ast-cli-import-local-report --host http://localhost:5000 --application java-test-project --report examples/test_projects/coverity-report.json --scan coverity')
        sys.exit()

    post_request(url, app, report, scan)
