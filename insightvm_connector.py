# --
# File: insightvm_connector.py
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

# Phantom App imports
import phantom.app as phantom

# Imports local to this App
import insightvm_consts as consts

from lxml import etree

import time
import requests
import xmltodict
import simplejson as json
from datetime import datetime


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

        params = {'user-id': config[phantom.APP_JSON_USERNAME],
                'password': config[phantom.APP_JSON_PASSWORD]}

        ret_val, resp_data = self._make_soap_call(action_result, endpoint, params)

        if not ret_val:
            return ret_val

        self._session_id = dict(resp_data).get('LoginResponse', {}).get('@session-id')

        if not self._session_id:
            return action_result.set_status(phantom.APP_ERROR, consts.INSIGHTVM_ERR_NO_SESSION_ID)

        return phantom.APP_SUCCESS

    def _make_soap_call(self, action_result, endpoint, param_dict):

        config = self.get_config()

        root = etree.Element(endpoint)

        for k, v in param_dict.iteritems():
            root.set(k, v)

        if endpoint != 'LoginRequest':
            root.set('session-id', self._session_id)

        try:
            response = requests.post(self._base_url, data=etree.tostring(root), headers=self._headers, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, consts.INSIGHTVM_ERR_SERVER_CONNECTION, e), None

        resp_xml = etree.fromstring(response.content)

        try:

            resp_json = json.loads(json.dumps(xmltodict.parse(etree.tostring(resp_xml))))

            if (response.status_code != 200):
                return action_result.set_status(phantom.APP_ERROR, consts.INSIGHTVM_ERR_BAD_STATUS), None

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, consts.INSIGHTVM_ERR_PARSE_XML, e), None

        return action_result.set_status(phantom.APP_SUCCESS), resp_json

    def _response_stripper(self, strippee, ret_dict):

        for k, v in strippee.iteritems():

            if k.startswith('@'):
                k = k[1:]

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
            self.save_progress("Test connectivity failed")
            return action_result.get_status()

        endpoint = 'SystemInformationRequest'

        ret_val, resp_data = self._make_soap_call(action_result, endpoint, {})

        version = 'Unknown'
        for stat in dict(resp_data).get('SystemInformationResponse', {}).get('StatisticsInformationSummary', {}).get('Statistic', {}):
            if stat['@name'] == 'nsc-version':
                version = stat['#text']

        self.save_progress("Detected InsightVM version {0}".format(version))

        self.save_progress("Test connectivity passed")

        return phantom.APP_SUCCESS

    def _list_sites(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if not self._login(action_result):
            return action_result.get_status()

        endpoint = 'SiteListingRequest'

        ret_val, resp_data = self._make_soap_call(action_result, endpoint, {})

        if not ret_val:
            return ret_val

        stripped_data = {}
        self._response_stripper(resp_data, stripped_data)

        action_result.add_data(stripped_data)

        action_result.set_summary({'num_sites': len(stripped_data.get('SiteListingResponse', {}).get('SiteSummary', []))})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):

        config = self.get_config()
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if not self._login(action_result):
            return action_result.get_status()

        endpoint = 'SiteScanHistoryRequest'

        ret_val, resp_data = self._make_soap_call(action_result, endpoint, {'site-id': str(config['site'])})

        count = 0
        last_time = self._state.get('last_time', 0)

        if not self.is_poll_now():
            self._state['last_time'] = time.time()
        else:
            max_containers = param.get('container_count', consts.INSIGHTVM_DEFAULT_CONTAINER_COUNT)

        for scan in dict(resp_data).get('SiteScanHistoryResponse', {}).get('ScanSummary', []):

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
            container['name'] = scan['@scan-id']
            container['source_data_identifier'] = scan['@scan-id']
            container['label'] = config.get('ingest', {}).get('container_label')
            container['description'] = 'Scan {0} for Site {1}'.format(scan['@scan-id'], scan['@site-id'])

            ret_val, message, container_id = self.save_container(container)

            if not ret_val:
                continue

            scan_artifact = {}
            scan_artifact['label'] = 'scan'
            scan_artifact['name'] = 'Scan Artifact'
            scan_artifact['container_id'] = container_id
            scan_artifact['source_data_identifier'] = scan['@scan-id']
            scan_artifact['cef'] = {'scan-id': scan['@scan-id'],
                    'startTime': scan['@startTime'],
                    'engineId': scan['@engine-id'],
                    'endTime': scan['@endTime'],
                    'siteId': scan['@scan-id'],
                    'status': scan['@status'],
                    'name': scan['@name']}

            total = 0
            artifacts = {}
            for vuln in scan['vulnerabilities']:

                if vuln['@status'] not in artifacts:

                    artifact = {}
                    artifacts[vuln['@status']] = artifact

                    artifact['cef'] = {'total': 0}
                    artifact['name'] = vuln['@status']
                    artifact['label'] = 'vulnerability'
                    artifact['container_id'] = container_id
                    artifact['source_data_identifier'] = scan['@scan-id']

                else:
                    artifact = artifacts[vuln['@status']]

                total += int(vuln['@count'])
                artifact['cef']['total'] = str(int(artifact['cef']['total']) + int(vuln['@count']))

                if vuln.get('@severity') is not None:
                    artifact['cef']['sev{0}'.format(vuln['@severity'])] = vuln['@count']

            ret_val, message, artifact_id = self.save_artifacts(artifacts.values())

            scan_artifact['cef']['vulnerabilities'] = str(total)
            ret_val, message, artifact_id = self.save_artifact(scan_artifact)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = None

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_LIST_SITES):
            ret_val = self._list_sites(param)
        elif (action_id == self.ACTION_ID_ON_POLL):
            ret_val = self._on_poll(param)
        elif (action_id == self.ACTION_ID_TEST_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import sys
    # import pudb
    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = InsightVMConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
