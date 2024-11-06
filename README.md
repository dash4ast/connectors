## dash4ast

dash4ast automatically consolidates, de-duplicates and manages results from commercial and open source SAST, DAST, SCA, IAC and Image Containers. Have all your metrics in one place with [dash4ast](www.dash4ast.com).

![alt text](https://securingsoftware.files.wordpress.com/2022/08/analytics.png)

## Getting started

To install dash4ast in your environment, execute next commands:

```
git clone https://gitlab.com/dash4ast-community1/support.git
cd support
sudo docker-compose up -d (or sudo docker compose up -d)
```
To populate with some data, execute the script:
```
./load-demo-data.sh
```

Then:
Access to dash4ast through: http://localhost:3838/dash4ast

![alt text](https://securingsoftware.files.wordpress.com/2022/08/login.png)

Use dash4ast/demo

## Requirements:

* Docker -> https://docs.docker.com/engine/install/
* Docker-compose -> https://docs.docker.com/compose/install/
* Git
* Open Ports: 3838, 5001, 5433

## Integration with your security tools in a CI/CD pipeline

- Use dash4ast client in the following way:

```
python3 client/dash4ast-cli-import-local-report.py --host ${DASH4AST_ENDPOINT_QA} --application YOUR_DASH4AST_APP --report REPORT_PATH --scan SCAN_TOOL
```

Where:
* DASH4AST_ENDPOINT_QA is http://localhost:5000 if installed locally
* YOUR_APP is the name of your application
* REPORT_PATH is the path to the report, example, /tmp/bandit-output.json
* SCAN_TOOL is the security tool that has generated the report. It can be: bandit, safety, checkov, kiuwan, Coverity, trivy, snyk, checkmark, owaspdep, owaspzap.

- Blackduck and Sonarqube have direct connection (not needed to specify a report file)

Example:

* **Blackduck**

```
python3 client/dash4ast-cli-import-blackduck-report.py --host ${DASH4AST_ENDPOINT_QA} --application-tool YOUR_APP_IN_BLACKDUCK --application-dash4ast YOUR_APP_IN_DASH4AST --url-tool https://xxxx.blackduck.com --api-key-tool xxxx'
```

* **Sonarqube**
```
python3 client/dash4ast-cli-import-sonarqube-report.py --host ${DASH4AST_ENDPOINT_QA} --application-tool YOUR_APP_IN_SONARQUBE --application-dash4ast YOUR_APP_IN_DASH4AST --url-tool https://xxxx.blackduck.com --user-tool xxxx --pwd-tool xxxx'
```
![alt text](https://securingsoftware.files.wordpress.com/2022/08/connectors.png)

## Connectors

Full list of available connectors:
* bandit (json report). API and interface.
* owaszap (xml report). API and interface.
* checkov (json report). API and interface.
* Coverity (json report). API and interface.
* safety (json report). API and interface.
* semgrep (json report). API and interface.
* kiuwan (csv import). Interface.
* snyk (json import). Interface.
* trivy (json import). Interface.
* checkmark (csv import). Interface.
* sonarqube (direct connection)
* blackduck (direct connection)
* hclscan (xml report). API and interface.

Coming soon:
* owasp dependency check

## How to develop new connectors
See guide here:
https://gitlab.com/dash4ast-community1/support/-/wikis/How-to-develop-a-new-connector

## Authors & Contact

Please contact:
Sebastian Revuelta -> https://www.linkedin.com/in/sebasrevuelta/
