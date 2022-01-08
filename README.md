[comment]: # "Auto-generated SOAR connector documentation"
# InsightVM

Publisher: Splunk
Connector Version: 2\.0\.3
Product Vendor: Rapid7
Product Name: InsightVM
Product Version Supported (regex): "\.\*"
Minimum Product Version: 4\.9\.39220

This app integrates with Rapid7 InsightVM \(formerly Nexpose\) to ingest scan data

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
[test connectivity](#action-test-connectivity) - Checks authentication with the InsightVM instance
[list sites](#action-list-sites) - List all sites found on the InsightVM instance
[on poll](#action-on-poll) - Ingest scan data from InsightVM

## action: 'test connectivity'
Checks authentication with the InsightVM instance

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
action\_result\.data\.\*\.siteListingResponse\.siteSummary\.\*\.description | string |
action\_result\.data\.\*\.siteListingResponse\.siteSummary\.\*\.id | string |
action\_result\.data\.\*\.siteListingResponse\.siteSummary\.\*\.name | string |
action\_result\.data\.\*\.siteListingResponse\.siteSummary\.\*\.riskfactor | string |
action\_result\.data\.\*\.siteListingResponse\.siteSummary\.\*\.riskscore | string |
action\_result\.data\.\*\.siteListingResponse\.success | string |
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
