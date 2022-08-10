[comment]: # "Auto-generated SOAR connector documentation"
# InsightVM

Publisher: Splunk  
Connector Version: 3\.2\.0  
Product Vendor: Rapid7  
Product Name: InsightVM  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.0  

This app integrates with Rapid7 InsightVM \(formerly Nexpose\) to ingest scan data and perform investigative actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2017-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
### Note:

-   For version 3.0.0: artifacts ingested during 'on poll' have changed and data paths for the 'list
    sites' action have also changed due to underlying API changes. Thus, It is recommended that
    users update their playbooks accordingly.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a InsightVM asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**device** |  required  | string | IP or hostname
**port** |  required  | numeric | Port
**username** |  required  | string | Username
**password** |  required  | password | Password
**site** |  required  | numeric | ID of site to ingest from
**verify\_server\_cert** |  optional  | boolean | Verify server certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Check authentication with the InsightVM instance  
[list sites](#action-list-sites) - List all sites found on the InsightVM instance  
[on poll](#action-on-poll) - Ingest scan data from InsightVM  
[find assets](#action-find-assets) - Find assets on the InsightVM instance  
[get asset vulnerabilities](#action-get-asset-vulnerabilities) - Retrieve all vulnerability findings on an asset  

## action: 'test connectivity'
Check authentication with the InsightVM instance

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list sites'
List all sites found on the InsightVM instance

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.assets | numeric | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.importance | string | 
action\_result\.data\.\*\.lastScanTime | string | 
action\_result\.data\.\*\.links\.\*\.href | string | 
action\_result\.data\.\*\.links\.\*\.rel | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.riskScore | numeric | 
action\_result\.data\.\*\.scanEngine | numeric | 
action\_result\.data\.\*\.scanTemplate | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.vulnerabilities\.critical | numeric | 
action\_result\.data\.\*\.vulnerabilities\.moderate | numeric | 
action\_result\.data\.\*\.vulnerabilities\.severe | numeric | 
action\_result\.data\.\*\.vulnerabilities\.total | numeric | 
action\_result\.summary | string | 
action\_result\.summary\.num\_sites | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Ingest scan data from InsightVM

Type: **ingest**  
Read only: **True**

Basic configuration parameters for this action are available in asset configuration\.<br><br>Only scan data from the site specified in the <b>site</b> asset configuration parameter will be ingested\.<br><br>The app will create a container for each scan that has been completed on the site since the last polling interval\. Each container will have an artifact with information about the scan with the following CEF fields\:<ul><li>siteId</li><li>scanId</li><li>engineId</li><li>startTime</li><li>endTime</li><li>status</li><li>vulnerabilities</li><li>nodes</li><li>tasks</li></ul>The other artifacts in the container will contain data about the vulnerabilities detected during the scan with each having a CEF field with a count of vulnerabilities found\. If the information is available, CEF fields will be created with counts for different severity levels for each vulnerability\. The container and all artifacts will be given a medium severity\.<br><br>POLL NOW will ingest the oldest scans up to a maximum specified by <b>container\_count</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**container\_id** |  optional  | Parameter ignored in this app | string | 
**container\_count** |  optional  | Maximum numer of reports to ingest during poll now | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'find assets'
Find assets on the InsightVM instance

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filters** |  required  | Filters used to match assets | string | 
**match** |  required  | Operator to determine how to match filters | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filters | string | 
action\_result\.parameter\.match | string | 
action\_result\.data\.\*\.addresses\.\*\.ip | string | 
action\_result\.data\.\*\.addresses\.\*\.mac | string | 
action\_result\.data\.\*\.assessedForPolicies | boolean | 
action\_result\.data\.\*\.assessedForVulnerabilities | boolean | 
action\_result\.data\.\*\.history\.\*\.date | string | 
action\_result\.data\.\*\.history\.\*\.scanId | numeric | 
action\_result\.data\.\*\.history\.\*\.type | string | 
action\_result\.data\.\*\.history\.\*\.version | numeric | 
action\_result\.data\.\*\.hostName | string | 
action\_result\.data\.\*\.hostNames\.\*\.name | string | 
action\_result\.data\.\*\.hostNames\.\*\.source | string | 
action\_result\.data\.\*\.id | numeric |  `insightvm asset id` 
action\_result\.data\.\*\.ids\.\*\.id | string | 
action\_result\.data\.\*\.ids\.\*\.source | string | 
action\_result\.data\.\*\.ip | string | 
action\_result\.data\.\*\.links\.\*\.href | string | 
action\_result\.data\.\*\.links\.\*\.rel | string | 
action\_result\.data\.\*\.mac | string | 
action\_result\.data\.\*\.os | string | 
action\_result\.data\.\*\.osFingerprint\.architecture | string | 
action\_result\.data\.\*\.osFingerprint\.description | string | 
action\_result\.data\.\*\.osFingerprint\.family | string | 
action\_result\.data\.\*\.osFingerprint\.id | numeric | 
action\_result\.data\.\*\.osFingerprint\.product | string | 
action\_result\.data\.\*\.osFingerprint\.systemName | string | 
action\_result\.data\.\*\.osFingerprint\.type | string | 
action\_result\.data\.\*\.osFingerprint\.vendor | string | 
action\_result\.data\.\*\.osFingerprint\.version | string | 
action\_result\.data\.\*\.rawRiskScore | numeric | 
action\_result\.data\.\*\.riskScore | numeric | 
action\_result\.data\.\*\.services\.\*\.configurations\.\*\.name | string | 
action\_result\.data\.\*\.services\.\*\.configurations\.\*\.value | string | 
action\_result\.data\.\*\.services\.\*\.family | string | 
action\_result\.data\.\*\.services\.\*\.links\.\*\.href | string | 
action\_result\.data\.\*\.services\.\*\.links\.\*\.rel | string | 
action\_result\.data\.\*\.services\.\*\.name | string | 
action\_result\.data\.\*\.services\.\*\.port | numeric | 
action\_result\.data\.\*\.services\.\*\.product | string | 
action\_result\.data\.\*\.services\.\*\.protocol | string | 
action\_result\.data\.\*\.services\.\*\.vendor | string | 
action\_result\.data\.\*\.services\.\*\.version | string | 
action\_result\.data\.\*\.software\.\*\.description | string | 
action\_result\.data\.\*\.software\.\*\.family | string | 
action\_result\.data\.\*\.software\.\*\.id | numeric | 
action\_result\.data\.\*\.software\.\*\.product | string | 
action\_result\.data\.\*\.software\.\*\.type | string | 
action\_result\.data\.\*\.software\.\*\.vendor | string | 
action\_result\.data\.\*\.software\.\*\.version | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.userGroups\.\*\.id | numeric | 
action\_result\.data\.\*\.userGroups\.\*\.name | string | 
action\_result\.data\.\*\.users\.\*\.fullName | string | 
action\_result\.data\.\*\.users\.\*\.id | numeric | 
action\_result\.data\.\*\.users\.\*\.name | string | 
action\_result\.data\.\*\.vulnerabilities\.critical | numeric | 
action\_result\.data\.\*\.vulnerabilities\.exploits | numeric | 
action\_result\.data\.\*\.vulnerabilities\.malwareKits | numeric | 
action\_result\.data\.\*\.vulnerabilities\.moderate | numeric | 
action\_result\.data\.\*\.vulnerabilities\.severe | numeric | 
action\_result\.data\.\*\.vulnerabilities\.total | numeric | 
action\_result\.summary | string | 
action\_result\.summary\.num\_assets | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get asset vulnerabilities'
Retrieve all vulnerability findings on an asset

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**asset\_id** |  required  | The identifier of the asset | numeric |  `insightvm asset id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.asset\_id | numeric |  `insightvm asset id` 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.instances | numeric | 
action\_result\.data\.\*\.links\.\*\.href | string | 
action\_result\.data\.\*\.links\.\*\.id | string | 
action\_result\.data\.\*\.links\.\*\.rel | string | 
action\_result\.data\.\*\.results\.\*\.checkId | string | 
action\_result\.data\.\*\.results\.\*\.key | string | 
action\_result\.data\.\*\.results\.\*\.port | numeric | 
action\_result\.data\.\*\.results\.\*\.proof | string | 
action\_result\.data\.\*\.results\.\*\.protocol | string | 
action\_result\.data\.\*\.results\.\*\.since | string | 
action\_result\.data\.\*\.results\.\*\.status | string | 
action\_result\.data\.\*\.since | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.number\_of\_vulnerabilities | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 