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
import xmltodict
from bs4 import BeautifulSoup
from defusedxml import ElementTree
from lxml import etree

import insightvm_consts as consts


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


# Define the App Class
class InsightVMConnector(phantom.BaseConnector):
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_LIST_SITES = "list_sites"
    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"

    def __init__(self):

        # Call the BaseConnectors init first
        super(InsightVMConnector, self).__init__()

        self._base_url = None
        self._session_id = None
        self._state = None
        self._headers = {'Content-Type': 'application/xml'}

    def initialize(self):

        config = self.get_config()

        self._base_url = consts.INSIGHTVM_API_URL.format(config[phantom.APP_JSON_DEVICE], config[phantom.APP_JSON_PORT])

        self._state = self.load_state()

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _login(self, action_result):

        config = self.get_config()

        endpoint = 'LoginRequest'

        params = {'user-id': config[phantom.APP_JSON_USERNAME], 'password': config[phantom.APP_JSON_PASSWORD]}

        ret_val, resp_data = self._make_soap_call(action_result, endpoint, params)

        if not ret_val:
            return ret_val

        self._session_id = dict(resp_data).get('LoginResponse', {}).get('@session-id')

        if not self._session_id:
            return action_result.set_status(phantom.APP_ERROR, consts.INSIGHTVM_ERR_NO_SESSION_ID)

        return phantom.APP_SUCCESS

    def _process_request_exception(self, exception):

        addition = ''
        e_str = str(exception)
        if 'Max retries exceeded' in e_str:
            addition = consts.INSIGHTVM_ERR_BAD_IP
        elif 'bad handshake' in e_str or '_ssl.c:504' in e_str:
            addition = consts.INSIGHTVM_ERR_BAD_CERT

        if not addition:
            return consts.INSIGHTVM_ERR_SERVER_CONNECTION.format(exception)

        self.save_progress(consts.INSIGHTVM_ERR_SERVER_CONNECTION.format(exception))
        return addition

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_xml_response(self, r, action_result, endpoint):

        # Try an xml parse
        try:
            resp_xml = ElementTree.fromstring(r.content)
            resp_json = json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(resp_xml))))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "{0}: {1}".format(consts.INSIGHTVM_ERR_PARSE_XML, e)), None

        if r.status_code != 200:
            action_result.add_data(resp_json)
            message = r.text.replace('{', '{{').replace('}', '}}')
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error from server, Status Code: {0} data returned: {1}".format(
                r.status_code, message)), resp_json)

        resp_str = endpoint.replace('Request', 'Response')

        if int(resp_json.get(resp_str, {}).get('@success', '0')):
            return RetVal(phantom.APP_SUCCESS, resp_json)

        xml_root = resp_json.get(resp_str)
        if not xml_root:
            xml_root = resp_json.get('XMLResponse', {})

        message = xml_root.get('Failure', {}).get('Exception', {}).get('message')
        if not message:
            message = r.text.replace('{', '{{').replace('}', '}}')
        elif message == consts.INSIGHTVM_ERR_NEED_AUTH:
            message = consts.INSIGHTVM_ERR_BAD_CREDS

        action_result.add_data(resp_json)
        return RetVal(action_result.set_status(phantom.APP_ERROR, "Error from server, Status Code: {0} data returned: {1}".format(
            r.status_code, message)), resp_json)

    def _process_response(self, r, action_result, endpoint):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            if r is not None:
                action_result.add_debug_data({'r_status_code': r.status_code})
                action_result.add_debug_data({'r_text': r.text})
                action_result.add_debug_data({'r_headers': r.headers})
            else:
                action_result.add_debug_data({'r_text': 'r is None'})
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Got no response from InsightVM instance"), None)

        # There are just too many differences in the response to handle all of them in the same function
        if 'xml' in r.headers.get('Content-Type', ''):
            return self._process_xml_response(r, action_result, endpoint)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successfull empty reponse
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_soap_call(self, action_result, endpoint, param_dict):

        config = self.get_config()

        root = etree.Element(endpoint)

        for k, v in param_dict.items():
            root.set(k, v)

        if endpoint != 'LoginRequest':
            root.set('session-id', self._session_id)

        try:
            response = requests.post(self._base_url, data=ElementTree.tostring(root), headers=self._headers,
                timeout=consts.INSIGHTVM_DEFAULT_TIMEOUT, verify=config.get(phantom.APP_JSON_VERIFY, False))
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, self._process_request_exception(e)), None)

        return self._process_response(response, action_result, endpoint)

    def _response_stripper(self, strippee, ret_dict):

        for k, v in strippee.items():

            k = k.replace('@', '')
            if '-' in k:
                k = k.replace('-', ' ')
                k = k.title()
            k = k.replace(' ', '')
            k = k[0].lower() + k[1:]

            if type(v) == dict:
                ret_dict[k] = {}
                self._response_stripper(v, ret_dict[k])

            elif type(v) == list:
                ret_dict[k] = []
                for i in v:
                    new_dict = {}
                    self._response_stripper(i, new_dict)
                    ret_dict[k].append(new_dict)

            else:
                ret_dict[k] = v

    def _test_connectivity(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if not self._login(action_result):
            self.save_progress(consts.INSIGHTVM_ERR_TEST_CONNECTIVITY)
            return action_result.get_status()

        endpoint = 'SystemInformationRequest'

        ret_val, resp_data = self._make_soap_call(action_result, endpoint, {})

        version = 'Unknown'
        for stat in dict(resp_data).get('SystemInformationResponse', {}).get('StatisticsInformationSummary', {}).get('Statistic', {}):
            if stat['@name'] == 'nsc-version':
                version = stat['#text']

        self.save_progress("Detected InsightVM version {0}".format(version))

        if not self._check_for_site(action_result, self.get_config()['site']):
            self.save_progress(consts.INSIGHTVM_ERR_TEST_CONNECTIVITY)
            return action_result.set_status(phantom.APP_ERROR, consts.INSIGHTVM_ERR_BAD_SITE)

        self.save_progress(consts.INSIGHT_SUCCESS_TEST_CONNECTIVITY)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_for_site(self, action_result, site):

        sites = self._get_sites(action_result)

        if sites is None:
            return False

        sites = [int(x.get('id')) for x in sites.get('siteListingResponse', {}).get('siteSummary', [])]

        if int(site) not in sites:
            return False
        return True

    def _get_sites(self, action_result):

        endpoint = 'SiteListingRequest'

        ret_val, resp_data = self._make_soap_call(action_result, endpoint, {})

        if not ret_val:
            return None

        stripped_data = {}
        self._response_stripper(resp_data, stripped_data)

        return stripped_data

    def _list_sites(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if not self._login(action_result):
            return action_result.get_status()

        sites = self._get_sites(action_result)

        if sites is None:
            return phantom.APP_ERROR

        action_result.add_data(sites)

        action_result.set_summary({'num_sites': len(sites.get('siteListingResponse', {}).get('siteSummary', []))})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):

        config = self.get_config()
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if not self._login(action_result):
            return action_result.get_status()

        if not self._check_for_site(action_result, config['site']):
            return action_result.set_status(phantom.APP_ERROR, consts.INSIGHTVM_ERR_BAD_SITE)

        endpoint = 'SiteScanHistoryRequest'

        ret_val, resp_data = self._make_soap_call(action_result, endpoint, {'site-id': str(config['site'])})

        count = 0
        max_containers = 0
        last_time = self._state.get('last_time', 0)

        if not self.is_poll_now():
            self._state['last_time'] = time.time()
        else:
            max_containers = param.get('container_count', consts.INSIGHTVM_DEFAULT_CONTAINER_COUNT)

        scan_data = dict(resp_data).get('SiteScanHistoryResponse', {}).get('ScanSummary', [])

        if isinstance(scan_data, dict):
            scan_data = [scan_data]

        for scan in scan_data:

            if scan['@status'] != 'finished':
                continue

            if self.is_poll_now():
                if count >= max_containers:
                    break
                count += 1

            else:
                finished_datetime = datetime.strptime(scan['@endTime'], "%Y%m%dT%H%M%S%f")
                finished_epoch = (finished_datetime - datetime.utcfromtimestamp(0)).total_seconds()
                if finished_epoch < last_time:
                    continue

            container = {}
            container['name'] = "Scan ID {0}".format(scan['@scan-id'])
            container['source_data_identifier'] = scan['@scan-id']
            container['label'] = config.get('ingest', {}).get('container_label')
            container['description'] = 'Scan {0} for Site {1}'.format(scan['@scan-id'], scan['@site-id'])

            ret_val, message, container_id = self.save_container(container)

            if not ret_val:
                continue

            scan_artifact = {}
            scan_artifact['cef'] = {}
            scan_artifact['type'] = 'scan'
            scan_artifact['label'] = 'scan'
            scan_artifact['name'] = 'Scan Artifact'
            scan_artifact['container_id'] = container_id
            scan_artifact['source_data_identifier'] = scan['@scan-id']
            scan_artifact['cef_types'] = {'scanId': ['insightvm scan id']}

            self._response_stripper(scan, scan_artifact['cef'])

            total = 0
            artifacts = {}
            for vuln in scan['vulnerabilities']:

                if vuln['@status'] not in artifacts:

                    artifact = {}
                    artifacts[vuln['@status']] = artifact

                    artifact['cef'] = {'total': 0}
                    artifact['name'] = vuln['@status']
                    artifact['type'] = 'vulnerability'
                    artifact['label'] = 'vulnerability'
                    artifact['container_id'] = container_id
                    artifact['source_data_identifier'] = scan['@scan-id']

                else:
                    artifact = artifacts[vuln['@status']]

                total += int(vuln['@count'])
                artifact['cef']['total'] = int(artifact['cef']['total']) + int(vuln['@count'])

                if vuln.get('@severity') is not None:
                    artifact['cef']['sev{0}'.format(vuln['@severity'])] = vuln['@count']

            ret_val, message, artifact_id = self.save_artifacts(list(artifacts.values()))

            scan_artifact['cef']['vulnerabilities'] = str(total)
            ret_val, message, artifact_id = self.save_artifact(list(scan_artifact))

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
        elif action_id == self.ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._test_connectivity(param)

        return ret_val


def main():
    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

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
            login_url = InsightVMConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, timeout=consts.INSIGHTVM_DEFAULT_TIMEOUT, verify=True)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=True, data=data, headers=headers, timeout=consts.INSIGHTVM_DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
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
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    exit(0)


if __name__ == '__main__':
    main()
