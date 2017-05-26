# --
# File: insightvm_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

INSIGHTVM_ERR_BAD_STATUS = "Call to InsightVM failed"
INSIGHTVM_ERR_TEST_CONNECTIVITY = "Test connectivity failed"
INSIGHTVM_ERR_NEED_AUTH = "Authorization required for API access"
INSIGHTVM_ERR_PARSE_XML = "Could not parse XML response from InsightVM server"
INSIGHTVM_ERR_BAD_SITE = "The given site could not be found on the InsightVM server"
INSIGHTVM_ERR_BAD_IP = "This error usually indicates that the IP or port is incorrect"
INSIGHTVM_ERR_BAD_CREDS = "The provided credentials were rejected by the InsightVM server"
INSIGHTVM_ERR_NO_SESSION_ID = "Could not get session ID from login call to InsightVM server"
INSIGHTVM_ERR_SERVER_CONNECTION = "Could not connect to InsightVM server. Error string: {0}"
INSIGHTVM_ERR_BAD_CERT = "This error usually indicates that the certificate on the server is invalid"

INSIGHTVM_API_URL = "https://{0}:{1}/api/1.1/xml"

INSIGHTVM_DEFAULT_CONTAINER_COUNT = 10
