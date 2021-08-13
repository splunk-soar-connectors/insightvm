# --
# File: insightvm_consts.py
#
# Copyright (c) 2017-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

INSIGHTVM_ERR_BAD_STATUS = "Call to InsightVM failed"
INSIGHTVM_ERR_TEST_CONNECTIVITY = "Test Connectivity Failed"
INSIGHTVM_ERR_NEED_AUTH = "Authorization required for API access"
INSIGHTVM_ERR_PARSE_XML = "Could not parse XML response from InsightVM server"
INSIGHTVM_ERR_BAD_SITE = "The given site could not be found on the InsightVM server"
INSIGHTVM_ERR_BAD_IP = "This error usually indicates that the IP or port is incorrect"
INSIGHTVM_ERR_BAD_CREDS = "The provided credentials were rejected by the InsightVM server"
INSIGHTVM_ERR_NO_SESSION_ID = "Could not get session ID from login call to InsightVM server"
INSIGHTVM_ERR_SERVER_CONNECTION = "Could not connect to the InsightVM server. Error string: {0}"
INSIGHTVM_ERR_BAD_CERT = "This error usually indicates that the certificate on the server could not be verified"

INSIGHT_SUCCESS_TEST_CONNECTIVITY = "Test Connectivity Passed"

INSIGHTVM_API_URL = "https://{0}:{1}/api/1.1/xml"

INSIGHTVM_DEFAULT_CONTAINER_COUNT = 10
