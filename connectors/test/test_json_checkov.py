import requests
import json
import hashlib


def post_request():

    url = 'http://localhost:5000/checkov_json_import'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    report = open('/home/sebas/tas/source/dash4ast/tool/connectors/test/checkov-output.json', 'r').read()
    application = 'dash4ast_global'
    logging.info(url)
    data = {'dash4ast_application': application, 'report': report}
    r = requests.post(url, json=data, headers=headers)
    logging.info(r.text)


def parse_report():
    logging.info('checkov report')
    report = open('checkov-output.json', 'r').read()
    content = json.loads(report)
    for check_types in content:
        for issue in check_types['results']['failed_checks']:
            if issue['check_result']['result'] == 'FAILED':
                logging.info(hashlib.sha256(str(issue['check_id']).encode()).hexdigest())
                logging.info(issue['check_id'])
                logging.info(issue['check_name'])
                logging.info(issue['file_abs_path'])
                logging.info(issue['file_line_range'])
                logging.info(issue['guideline'])
                if issue['severity'] is None:
                    logging.info('MEDIUM')


if __name__ == "__main__":
    ## post_request()
    parse_report()


