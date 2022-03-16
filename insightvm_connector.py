# File: insightvm_connector.py
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
#
#
import json
import time
from datetime import datetime
from sys import exit

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth

import insightvm_consts as consts


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


# Define the App Class
class InsightVMConnector(phantom.BaseConnector):
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_LIST_SITES = "list_sites"
    ACTION_ID_FIND_ASSETS = "find_assets"
    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"

    def __init__(self):

        # Call the BaseConnectors init first
        super(InsightVMConnector, self).__init__()

        self._base_url = None
        self._session_id = None
        self._state = None
        self._verify = None
        self._username = None
        self._password = None

    def initialize(self):

        config = self.get_config()

        self._base_url = consts.INSIGHTVM_API_URL.format(config[phantom.APP_JSON_DEVICE], config[phantom.APP_JSON_PORT])
        self._verify = config.get("verify_server_cert", False)
        self._username = config["username"]
        self._password = config["password"]
        self._state = self.load_state()

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
            None
        )

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))),
                None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(
        self,
        action_result,
        endpoint,
        headers=None,
        params=None,
        data=None,
        method="get",
    ):
        self.debug_print("Making rest call for: {}".format(self.get_action_identifier()))
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint
        self._auth = HTTPBasicAuth(self._username, self._password)

        try:
            r = request_func(
                url,
                auth=self._auth,
                json=data,
                headers=headers,
                params=params,
                verify=self._verify,
            )
        except Exception as e:
            self.debug_print("Got exception: {}".format(e))
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))),
                resp_json
            )

        return self._process_response(r, action_result)

    def _paginator(self, action_result, endpoint, headers=None, params=None, data=None, method="get", limit=None):

        items_list = list()

        if not params:
            params = {}

        page = 0
        params["size"] = consts.DEFAULT_MAX_RESULTS
        params["page"] = page

        while True:
            ret_val, items = self._make_rest_call(action_result, endpoint, headers=headers, params=params, data=data, method=method)

            if phantom.is_fail(ret_val):
                return None

            items_list.extend(items.get("resources"))

            if limit and len(items_list) >= limit:
                return items_list[:limit]

            if len(items.get("resources")) < consts.DEFAULT_MAX_RESULTS:
                break

            if len(items_list) == items.get("page").get("totalResources"):
                break

            page += 1
            params["page"] = page

        return items_list

    def _test_connectivity(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        endpoint = "/administration/info"

        ret_val, resp_data = self._make_rest_call(action_result, endpoint, {})

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        version = resp_data.get("version", {}).get("semantic", "Unknown")

        self.save_progress("Detected InsightVM version {0}".format(version))

        self.save_progress(consts.INSIGHT_SUCCESS_TEST_CONNECTIVITY)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_for_site(self, action_result, site_id):

        sites = self._get_sites(action_result)

        if sites is None:
            return False

        for site in sites:
            if site.get("id") == site_id:
                return True

        return False

    def _get_sites(self, action_result):

        endpoint = "/sites"

        resp_data = self._paginator(action_result=action_result, endpoint=endpoint)

        return resp_data

    def _list_sites(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        sites = self._get_sites(action_result)

        if sites is None:
            return phantom.APP_ERROR

        for site in sites:
            action_result.add_data(site)

        action_result.set_summary({"num_sites": len(sites)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _find_assets(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        endpoint = "/assets/search"

        payload = {
            'filters': json.loads(param['filters']),
            'match': param['match']
        }

        resp_data = self._paginator(action_result=action_result, endpoint=endpoint, data=payload, method='post')

        if resp_data is None:
            return phantom.APP_ERROR

        for asset in resp_data:
            action_result.add_data(asset)

        action_result.set_summary({"num_assets": len(resp_data)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):

        config = self.get_config()
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if not self._check_for_site(action_result, config["site"]):
            return action_result.set_status(phantom.APP_ERROR, consts.INSIGHTVM_ERR_BAD_SITE)

        endpoint = "/sites/{}/scans".format(config["site"])

        ret_val, resp_data = self._make_rest_call(action_result, endpoint)

        count = 0
        max_containers = 0
        last_time = self._state.get("last_time", 0)

        if not self.is_poll_now():
            self._state["last_time"] = time.time()
        else:
            max_containers = param.get("container_count", consts.INSIGHTVM_DEFAULT_CONTAINER_COUNT)

        scan_data = dict(resp_data).get("resources", [])

        if isinstance(scan_data, dict):
            scan_data = [scan_data]

        for scan in scan_data:
            self.save_progress("Ingesting scan id: {}".format(scan["id"]))
            if scan["status"] != "finished":
                continue

            if self.is_poll_now():
                if count >= max_containers:
                    break
                count += 1

            else:
                finished_datetime = datetime.strptime(scan["endTime"], "%Y-%m-%dT%H:%M:%S.%fZ")
                finished_epoch = (finished_datetime - datetime.utcfromtimestamp(0)).total_seconds()
                if finished_epoch < last_time:
                    continue

            container = {
                "name": "Scan ID {0}".format(scan["id"]),
                "source_data_identifier": scan["id"],
                "label": config.get("ingest", {}).get("container_label"),
                "description": "Scan {0} for Site {1}".format(scan["id"], config["site"]),
            }

            ret_val, message, container_id = self.save_container(container)

            if not ret_val:
                continue

            scan_artifact = {
                "cef": scan.get("vulnerabilities"),
                "type": "scan",
                "label": "scan",
                "name": "Scan Artifact",
                "container_id": container_id,
                "source_data_identifier": scan["id"],
                "cef_types": {"scanId": ["insightvm scan id"]},
            }

            ret_val, message, artifact_id = self.save_artifact(scan_artifact)

            if not ret_val:
                self.save_progress("Failed to save artifact: {}".format(message))
            else:
                self.save_progress("Artifact saved with id: {}".format(artifact_id))

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = None

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == self.ACTION_ID_LIST_SITES:
            ret_val = self._list_sites(param)
        elif action_id == self.ACTION_ID_ON_POLL:
            ret_val = self._on_poll(param)
        elif action_id == self.ACTION_ID_FIND_ASSETS:
            ret_val = self._find_assets(param)
        elif action_id == self.ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._test_connectivity(param)

        return ret_val


def main():
    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = InsightVMConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(
                login_url, timeout=consts.INSIGHTVM_DEFAULT_TIMEOUT, verify=True
            )
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(
                login_url,
                verify=True,
                data=data,
                headers=headers,
                timeout=consts.INSIGHTVM_DEFAULT_TIMEOUT,
            )
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: {}".format(str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = InsightVMConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    exit(0)


if __name__ == "__main__":
    main()
