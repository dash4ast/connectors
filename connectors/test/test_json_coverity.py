import requests
import json
import hashlib


def post_request():

    url = 'http://localhost:5000/coverity_json_import'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    report = open('/home/sebas/tas/source/dash4ast/tool/connectors/test/coverity-report.json', 'r').read()
    application = 'david3'

    data = {'dash4ast_application': application, 'report': report}
    r = requests.post(url, json=data, headers=headers)
    print(r.text)


def parse_report():
    report = open('coverity-report.json', 'r').read()
    content = json.loads(report)
    print(len(content['issues']))
    for issue in content['issues']:
        print(hashlib.md5(str(issue['mergeKey']).encode()).hexdigest())
        print(issue['checkerProperties']['subcategoryShortDescription'])
        print(issue['checkerName'])
        print(issue['checkerProperties']['impact'].upper())
        print("CWE: " + str(issue['checkerProperties']['cweCategory']))
        print(issue['strippedMainEventFilePathname'])
        print(issue['mainEventLineNumber'])


if __name__ == "__main__":
    post_request()
    parse_report()
