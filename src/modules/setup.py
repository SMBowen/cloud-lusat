import sys
import logging
import os
from datetime import datetime
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
import urllib3
import boto3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

##### define standard configurations ####

# SETUP LOGGIN OPTIONS
logging.basicConfig(stream=sys.stdout)
log = logging.getLogger("cloud-lusat-inventory-setup")
log.setLevel(logging.INFO)
# SETUP DATATIME FOR NOW
datetime_now = datetime.now()

# Setup for ELK general connection


def sendToELK(data):
    session = boto3.Session()
    credentials = session.get_credentials()
    access_key = credentials.access_key
    secret_key = credentials.secret_key
    session_token = credentials.token
    # Setup AWS ElasticAuth.
    awsauth = AWS4Auth(access_key, secret_key,
                       os.environ['AWS_REGION'], 'es', session_token=session_token)
    log.info(str(datetime_now) + ' starting sendtoelk function')
    index_name = 'inventory-' + datetime_now.strftime("%Y-%m-%d")
    elk_node = os.environ['elk_node']
    es = Elasticsearch(
        hosts=[{'host': elk_node, 'port': 443}],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=False,
        connection_class=RequestsHttpConnection,
        timeout=60,
        max_retries=10,
        retry_on_timeout=True
    )
    log.info(str(datetime_now) + " sending logs now")
    es.index(index=index_name, body=data)
    log.info(str(datetime_now) + " done")
