[comment]: # "Auto-generated SOAR connector documentation"
# Abnormal Security

Publisher: Splunk  
Connector Version: 1\.0\.1  
Product Vendor: Abnormal Security  
Product Name: Abnormal Security  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.0  

This app integrates with Abnormal Security to support various generic and investigative actions

# Splunk> Phantom

Welcome to the open-source repository for Splunk> Phantom's abnormalsecurity App.

Please have a look at our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) if you are interested in contributing, raising issues, or learning more about open-source Phantom apps.

## Legal and License

This Phantom App is licensed under the Apache 2.0 license. Please see our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md#legal-notice) for further details.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Abnormal Security asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Base URL
**access\_token** |  required  | password | Access Token

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[list threats](#action-list-threats) - Fetch the list of threat IDs which are in threat log  
[get threat details](#action-get-threat-details) - List threat details with the given threat ID  
[list abuse mailboxes](#action-list-abuse-mailboxes) - Fetch the list of abuse mailbox IDs  
[update threat status](#action-update-threat-status) - Change the status of threat with given threat ID  
[get threat status](#action-get-threat-status) - Fetch the status of threat  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list threats'
Fetch the list of threat IDs which are in threat log

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Limit the number of results to return \(Default 100\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data | string | 
action\_result\.data\.\*\.threatId | string |  `abnormal threat id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get threat details'
List threat details with the given threat ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**threat\_id** |  required  | A UUID representing the threat | string |  `abnormal threat id` 
**limit** |  optional  | Limit the number of results to return \(Default 100\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.threat\_id | string |  `abnormal threat id` 
action\_result\.data\.\*\.abxMessageId | numeric | 
action\_result\.data\.\*\.abxPortalUrl | string |  `url` 
action\_result\.data\.\*\.attachmentCount | numeric | 
action\_result\.data\.\*\.attackStrategy | string | 
action\_result\.data\.\*\.attackType | string | 
action\_result\.data\.\*\.attackVector | string | 
action\_result\.data\.\*\.attackedParty | string | 
action\_result\.data\.\*\.autoRemediated | boolean | 
action\_result\.data\.\*\.fromAddress | string |  `email` 
action\_result\.data\.\*\.fromName | string | 
action\_result\.data\.\*\.impersonatedParty | string | 
action\_result\.data\.\*\.internetMessageId | string | 
action\_result\.data\.\*\.isRead | boolean | 
action\_result\.data\.\*\.postRemediated | boolean | 
action\_result\.data\.\*\.receivedTime | string | 
action\_result\.data\.\*\.recipientAddress | string |  `email` 
action\_result\.data\.\*\.remediationStatus | string | 
action\_result\.data\.\*\.remediationTimestamp | string | 
action\_result\.data\.\*\.returnPath | string |  `email` 
action\_result\.data\.\*\.senderDomain | string |  `domain` 
action\_result\.data\.\*\.senderIpAddress | string | 
action\_result\.data\.\*\.sentTime | string | 
action\_result\.data\.\*\.subject | string | 
action\_result\.data\.\*\.summaryInsights | string | 
action\_result\.data\.\*\.threatId | string |  `abnormal threat id` 
action\_result\.data\.\*\.toAddresses | string |  `email` 
action\_result\.data\.\*\.urlCount | numeric | 
action\_result\.data\.\*\.urls | string |  `url` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list abuse mailboxes'
Fetch the list of abuse mailbox IDs

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Limit the number of results to return \(Default 100\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.campaignId | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update threat status'
Change the status of threat with given threat ID

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**threat\_id** |  required  | A UUID representing the threat | string |  `abnormal threat id` 
**action** |  required  | Action to update status for threat | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.action | string | 
action\_result\.parameter\.threat\_id | string |  `abnormal threat id` 
action\_result\.data\.\*\.action\_id | string |  `abnormal action id` 
action\_result\.data\.\*\.status\_url | string |  `url` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get threat status'
Fetch the status of threat

Type: **investigate**  
Read only: **True**

This action needs an action ID from update threat status action\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**threat\_id** |  required  | A UUID representing the threat | string |  `abnormal threat id` 
**action\_id** |  required  | A UUID representing the action | string |  `abnormal action id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.action\_id | string |  `abnormal action id` 
action\_result\.parameter\.threat\_id | string |  `abnormal threat id` 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 