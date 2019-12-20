# shodanExternalSpaceLookup.py
shodan API script to check whole ANS Public IP space for services published to the internet

## Prerequisites
* python 3+ 
* library - html shodan cefevent
* shodan account with API key
## Cronjob
0 * * * * /usr/local/bin/python3 /opt/shodan/shodanExternalSpaceLookup.py
