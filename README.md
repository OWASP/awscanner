# awscanner
# About 
Finds internet-exposed resources in an AWS account.
Results of the scan will be put in the results folder

https://owasp.org/www-project-awscanner/

# Installation
```shell script
git clone https://github.com/OWASP/awscanner.git
pip install aws-shell
cd awscanner
pip install -r requirements.txt 
```
# Usage 
```shell script
aws configure
python detector.py
```
