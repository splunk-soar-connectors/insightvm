# File: insightvm_consts.py
#
# Copyright (c) 2017-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
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

INSIGHTVM_DEFAULT_TIMEOUT = 30
