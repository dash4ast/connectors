python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5000 --application vulnerable-flask-app --report ./reports/vulnerable-flask-app/bandit-report.json --scan bandit
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5000 --application vulnerable-flask-app --report ./reports/vulnerable-flask-app/safety-report.json --scan safety
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5000 --application juice-shop --report ./reports/juice-shop/owaspzap-report.json --scan owaspzap

