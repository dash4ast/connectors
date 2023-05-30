## git clone source code examples
echo 'Cloning projects'
mkdir tmp
cd tmp
git clone vulnerable-flask-app
git clone webgoat-net
git clone connectors
git clone juice-shop
git clone webgoat-java
cd ..

## Run semgrep (SAST Java, Typescript)
echo 'Running semgrep scans'
semgrep scan --config auto --json --output ./reports/vulnerable-flask-app/semgrep-report.json ./tmp/vulnerable-flask-app
semgrep scan --config auto --json --output ./reports/webgoat/semgrep-report.json ./tmp/webgoat-net
semgrep scan --config auto --json --output ./reports/dash4ast/semgrep-report.json ./tmp/connectors
semgrep scan --config auto --json --output ./reports/dash4ast/semgrep-report.json ./tmp/juice-shop
semgrep scan --config auto --json --output ./reports/dash4ast/semgrep-report.json ./tmp/webgoat-java

## Run bandit (SAST Python)
echo 'Running bandit scans'
bandit -r -f json -o ./reports/vulnerable-flask-app/bandit-report.json vulnerable-flask-app/
bandit -r -f json -o ./reports/connectors/bandit-report.json connectors/

## Run safety (SCA-Python)
echo 'Running safety scans'
safety check -r vulnerable-flask-app/requirements.txt --json > ./reports/vulnerable-flask-app/safety-report.json
safety check -r connectors/connectors/requirements.txt --json > ./reports/connectors/safety-report.json

## Run Snyk (SCA)
echo 'Running snyk scans'
snyk test --file=connectors/connectors/setup.py --command=python3 --skip-unresolved --json > ./reports/connectors/snyk-report.json
## TODO: Run for juice-shop
## TODO: Run for webgot-java

## Run owasp zap (DAST)
#Run with docker command: demo.dash4ast.com
#Run with docker command: juice-shop (deploy locally first?)
#Run with docker command: web-goat (deploy locally first?)

## Run checkov (IAC)
## TODO: Run for connectors
## TODO: Run for webgoat-net
## TODO: Run for juice-shop
## TODO: Run for webgot-java
## TODO: Run for vulnerable-flask-app

## Run trivy (docker images)
# TODO...

## Remove temp folder
rm -rf ./tmp

###########################################################################################
#   Analysis type (tools)   SAST        SCA           DAST        IAC     Images
#
#   vulnerable-flask-app    X(bandit)   X(safety)      --      X(checkov)   --
#   webgoat-java            X(semgrep)  X(snyk)        Zap     X(checkov)   Trivy
#   connectors              X(semgrep)  X(snyk)        Zap     X(checkov)   Trivy
#   juice-shop              X(semgrep)  X(snyk)        Zap     X(checkov)   Trivy
#   webgoat-net             X(hclscan)  --              --     --           --
###########################################################################################


## Load Reports
# Vulnerable-flask-app
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application vulnerable-flask-app --report ./reports/vulnerable-flask-app/bandit-report.json --scan bandit
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application vulnerable-flask-app --report ./reports/vulnerable-flask-app/safety-report.json --scan safety
#python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application vulnerable-flask-app --report ./reports/vulnerable-flask-app/checkov-report.json --scan checkov

# webgoat-java
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application webgoat-java --report ./reports/webgoat/semgrep-report.json --scan semgrep
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application webgoat-java --report ./reports/webgoat/owaspzap-report.xml --scan owaspzap
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application webgoat-java --report ./reports/webgoat/snyk-report.json --scan snyk
#python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application webgoat-java --report ./reports/webgoat/checkov-report.json --scan checkov

# webgoat-net
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application demo-webgoat-net --report ./reports/webgoat/hclscan-report.xml --scan hclscan

# connectors
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application connectors --report ./reports/connectors/owaspzap-report.xml --scan owaspzap
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application test --report ./reports/connectors/snyk-report.xml --scan snyk
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application test --report ./reports/connectors/semgrep-report.xml --scan semgrep

# juice-shop
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application juice-shop --report ./reports/juice-shop/semgrep-report.json --scan semgrep
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application juice-shop --report ./reports/juice-shop/owaspzap-report.xml --scan owaspzap
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application juice-shop --report ./reports/juice-shop/snyk-report.xml --scan snyk

# test
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application test --report ./reports/tests/coverity-report.json --scan coverity

# spiracle
python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application juice-shop --report ./reports/spiracle/snyk-sca-report.xml --scan snyk
# python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application test --report ./reports/spiracle/checkmarx-report.json --scan checkmarx
# python3 ./client/dash4ast-cli-import-local-report.py --host http://localhost:5001 --application test --report ./reports/spiracle/kiuwan-report.json --scan kiuwan


## Just in case you have Blackduck, please, configure URL and API_TOKEN

#python3 ./client/dash4ast-cli-import-blackduck-report.py --host http://localhost:5001 --application-tool demo/webgoat --application-dash4ast webgoat --url-tool $BLACKDUCK_URL --api-key-tool $BLACKDUCK_API_TOKEN
#python3 ./client/dash4ast-cli-import-blackduck-report.py --host http://localhost:5001 --application-tool demo/dash4ast --application-dash4ast dash4ast --url-tool $BLACKDUCK_URL --api-key-tool $BLACKDUCK_API_TOKEN
#python3 ./client/dash4ast-cli-import-blackduck-report.py --host http://localhost:5001 --application-tool demo/vulnerable-flask-app --application-dash4ast vulnerable-flask-app --url-tool $BLACKDUCK_URL --api-key-tool $BLACKDUCK_API_TOKEN
#python3 ./client/dash4ast-cli-import-blackduck-report.py --host http://localhost:5001 --application-tool demo/chess --application-dash4ast chess --url-tool $BLACKDUCK_URL --api-key-tool $BLACKDUCK_API_TOKEN
#python3 ./client/dash4ast-cli-import-blackduck-report.py --host http://localhost:5001 --application-tool demo/juice-shop --application-dash4ast juice-shop --url-tool $BLACKDUCK_URL --api-key-tool $BLACKDUCK_API_TOKEN

