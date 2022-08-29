# dash4ast

dash4ast 


## Getting started

To make it easy for you to get started with GitLab, here's a list of recommended next steps.

```
git clone https://gitlab.com/dash4ast-community1/support.git
cd support
sudo docker-compose up -d (or sudo docker compose up -d)
```

Then:
Access to dash4ast through: http://localhost:3838/dash4ast

## Requirements:

* Docker
* Docker-compose
* Git
* Ports: 3838, 5000

## Integrate with your tools in a CI/CD pipeline

- Use client in the next way:

```
python3 dash4ast-cli-import.py --host ${DASH4AST_ENDPOINT_QA} --application YOUR_APP --report bandit-output.json --scan bandit
```

Where:
* DASH4AST_ENDPOINT_QA is http://localhost:5000 if installed locally
* scans can be: bandit, safety, checkov, kiuwan, coverity, trivy, snyk and so on

Note: Blackduck and Sonarqube has direct connection (not needed to specify a report file)

## Authors & Contact

Please contact:
Sebastian Revuelta -> https://www.linkedin.com/in/sebasrevuelta/

