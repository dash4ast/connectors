python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application vulnerable-flask-app --report ./reports/vulnerable-flask-app/bandit-report.json --scan bandit
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application vulnerable-flask-app --report ./reports/vulnerable-flask-app/safety-report.json --scan safety
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application vulnerable-flask-app --report ./reports/vulnerable-flask-app/semgrep-report.json --scan semgrep
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application webgoat --report ./reports/webgoat/semgrep-report.json --scan semgrep
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application dash4ast --report ./reports/dash4ast/owaspzap-report.xml --scan owaspzap
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application test --report ./reports/test_projects/safety-report.json --scan safety
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application test --report ./reports/test_projects/bandit-report.json --scan bandit
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application test --report ./reports/test_projects/coverity-report.json --scan coverity
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application juice-shop --report ./reports/juice-shop/semgrep-report.json --scan semgrep
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application juice-shop --report ./reports/juice-shop/owaspzap-report.xml --scan owaspzap

## Just in case you have Blackduck, please, configure URL and API_TOKEN

#python3 ./client/dash4ast-cli-import-blackduck-report.py --host http://localhost:5001 --application-tool demo/webgoat --application-dash4ast webgoat --url-tool $BLACKDUCK_URL --api-key-tool $BLACKDUCK_API_TOKEN
#python3 ./client/dash4ast-cli-import-blackduck-report.py --host http://localhost:5001 --application-tool demo/dash4ast --application-dash4ast dash4ast --url-tool $BLACKDUCK_URL --api-key-tool $BLACKDUCK_API_TOKEN
#python3 ./client/dash4ast-cli-import-blackduck-report.py --host http://localhost:5001 --application-tool demo/vulnerable-flask-app --application-dash4ast vulnerable-flask-app --url-tool $BLACKDUCK_URL --api-key-tool $BLACKDUCK_API_TOKEN
#python3 ./client/dash4ast-cli-import-blackduck-report.py --host http://localhost:5001 --application-tool demo/chess --application-dash4ast chess --url-tool $BLACKDUCK_URL --api-key-tool $BLACKDUCK_API_TOKEN
#python3 ./client/dash4ast-cli-import-blackduck-report.py --host http://localhost:5001 --application-tool demo/juice-shop --application-dash4ast juice-shop --url-tool $BLACKDUCK_URL --api-key-tool $BLACKDUCK_API_TOKEN

