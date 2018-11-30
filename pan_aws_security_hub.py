#!/usr/bin/env python
import boto3
import time
import json 
import re, os

from pan_lib import *
#from pandevice import policies 
from pan_lib import PAN_FW as pan_fw 
securityhub = boto3.client('securityhub')


direct_findings = [{  
   "AwsAccountId":"081476508764",
   "CreatedAt":"2018-11-21T15:44:50.866Z",
   "Description":"IP address 198.51.100.0 on the Tor Anonymizing Proxy network is communicating with EC2 instance i-99999999.",
   "FirstObservedAt":"2018-11-21T15:44:50.865Z",
   "GeneratorId":"arn:aws:guardduty:us-east-1:081476508764:detector/2eafe39b3fe0deb038f9063c281aa559",
   "Id":"arn:aws:guardduty:us-east-1:081476508764:detector/2eafe39b3fe0deb038f9063c281aa559/finding/ceb39b790458b07088188ac696f5fe5c",
   "LastObservedAt":"2018-11-25T19:45:09.748Z",
   "ProductArn":"arn:aws:securityhub:us-east-1::product/aws/guardduty",
   "ProductFields":{  
      "action/actionType":"NETWORK_CONNECTION",
      "action/networkConnectionAction/blocked":"false",
      "action/networkConnectionAction/connectionDirection":"INBOUND",
      "action/networkConnectionAction/localPortDetails/port":"80",
      "action/networkConnectionAction/localPortDetails/portName":"HTTP",
      "action/networkConnectionAction/protocol":"TCP",
      "action/networkConnectionAction/remoteIpDetails/city/cityName":"GeneratedFindingCityName",
      "action/networkConnectionAction/remoteIpDetails/country/countryName":"GeneratedFindingCountryName",
      "action/networkConnectionAction/remoteIpDetails/geoLocation/lat":"0",
      "action/networkConnectionAction/remoteIpDetails/geoLocation/lon":"0",
      "action/networkConnectionAction/remoteIpDetails/ipAddressV4":"69.181.214.105",
      "action/networkConnectionAction/remoteIpDetails/organization/asn":"-1",
      "action/networkConnectionAction/remoteIpDetails/organization/asnOrg":"GeneratedFindingASNOrg",
      "action/networkConnectionAction/remoteIpDetails/organization/isp":"GeneratedFindingISP",
      "action/networkConnectionAction/remoteIpDetails/organization/org":"GeneratedFindingORG",
      "action/networkConnectionAction/remotePortDetails/port":"39677",
      "action/networkConnectionAction/remotePortDetails/portName":"Unknown",
      "additionalInfo":"{\"sample\":true}",
      "archived":"false",
      "aws/securityhub/CompanyName":"AWS",
      "aws/securityhub/FindingId":"arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:081476508764:detector/2eafe39b3fe0deb038f9063c281aa559/finding/ceb39b790458b07088188ac696f5fe5c",
      "aws/securityhub/ProductName":"GuardDuty",
      "aws/securityhub/SeverityLabel":"MEDIUM",
      "count":"2",
      "detectorId":"2eafe39b3fe0deb038f9063c281aa559",
      "resourceRole":"TARGET"
   },
   "RecordState":"ACTIVE",
   "Resources":[  
      {  
         "Details":{  
            "AwsEc2Instance":{  
               "ImageId":"ami-99999999",
               "IpV4Addresses":[  
                  "198.51.100.0",
                  "10.0.0.1"
               ],
               "LaunchedAt":"2016-08-02T02:05:06.000Z",
               "SubnetId":"GeneratedFindingSubnetId",
               "Type":"m3.xlarge",
               "VpcId":"GeneratedFindingVPCId"
            }
         },
         "Id":"arn:aws:ec2:us-east-1:081476508764:instance/i-99999999",
         "Partition":"aws",
         "Region":"us-east-1",
         "Tags":{  
            "GeneratedFindingInstaceTag1":"GeneratedFindingInstaceValue1",
            "GeneratedFindingInstaceTag2":"GeneratedFindingInstaceTagValue2",
            "GeneratedFindingInstaceTag3":"GeneratedFindingInstaceTagValue3",
            "GeneratedFindingInstaceTag4":"GeneratedFindingInstaceTagValue4",
            "GeneratedFindingInstaceTag5":"GeneratedFindingInstaceTagValue5",
            "GeneratedFindingInstaceTag6":"GeneratedFindingInstaceTagValue6",
            "GeneratedFindingInstaceTag7":"GeneratedFindingInstaceTagValue7",
            "GeneratedFindingInstaceTag8":"GeneratedFindingInstaceTagValue8",
            "GeneratedFindingInstaceTag9":"GeneratedFindingInstaceTagValue9"
         },
         "Type":"AwsEc2Instance"
      }
   ],
   "SchemaVersion":"2018-10-08",
   "Severity":{  
      "Normalized":50,
      "Product":5
   },
   "Title":"Tor Exit node is communicating with EC2 instance i-99999999.",
   "Types":[  
      "TTPs/Command and Control/UnauthorizedAccess:EC2-TorIPCaller"
   ],
   "UpdatedAt":"2018-11-25T19:45:09.748Z",
   "WorkflowState":"NEW"
},
{
  "SchemaVersion": "2018-10-08",
  "Id": "arn:aws:guardduty:us-east-1:081476508764:detector/2eafe39b3fe0deb038f9063c281aa559/finding/56b39b790457e9cad83c292f725fd130",
  "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
  "GeneratorId": "arn:aws:guardduty:us-east-1:081476508764:detector/2eafe39b3fe0deb038f9063c281aa559",
  "AwsAccountId": "081476508764",
  "Types": [
    "TTPs/Discovery/Recon:IAMUser-MaliciousIPCaller"
  ],
  "FirstObservedAt": "2018-11-21T15:44:50.863Z",
  "LastObservedAt": "2018-11-25T19:45:09.745Z",
  "CreatedAt": "2018-11-21T15:44:50.863Z",
  "UpdatedAt": "2018-11-25T19:45:09.745Z",
  "Severity": {
    "Product": 5,
    "Normalized": 50
  },
  "Title": "Reconnaissance API GeneratedFindingAPIName was invoked from a known malicious IP address.",
  "Description": "API GeneratedFindingAPIName, commonly used in reconnaissance attacks, was invoked from a malicious IP address 198.51.100.0. Unauthorized actors perform such activity to gather information and discover resources like databases, S3 buckets etc., in order to further tailor the attack.",
  "ProductFields": {
    "detectorId": "2eafe39b3fe0deb038f9063c281aa559",
    "action/actionType": "AWS_API_CALL",
    "action/awsApiCallAction/api": "GeneratedFindingAPIName",
    "action/awsApiCallAction/serviceName": "GeneratedFindingAPIServiceName",
    "action/awsApiCallAction/callerType": "Remote IP",
    "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "198.51.100.0",
    "action/awsApiCallAction/remoteIpDetails/organization/asn": "-1",
    "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "GeneratedFindingASNOrg",
    "action/awsApiCallAction/remoteIpDetails/organization/isp": "GeneratedFindingISP",
    "action/awsApiCallAction/remoteIpDetails/organization/org": "GeneratedFindingORG",
    "action/awsApiCallAction/remoteIpDetails/country/countryName": "GeneratedFindingCountryName",
    "action/awsApiCallAction/remoteIpDetails/city/cityName": "GeneratedFindingCityName",
    "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "0",
    "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "0",
    "action/awsApiCallAction/affectedResources/AWS::EC2::Instance": "i-99999999",
    "action/awsApiCallAction/affectedResources/AWS::CloudTrail::Trail": "GeneratedFindingTrailName",
    "resourceRole": "TARGET",
    "additionalInfo": "{\"threatListName\":\"GeneratedFindingThreatListName\",\"unusual\":{\"isps\":\"amazon.com\"},\"sample\":true}",
    "archived": "false",
    "count": "2",
    "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:081476508764:detector/2eafe39b3fe0deb038f9063c281aa559/finding/56b39b790457e9cad83c292f725fd130",
    "aws/securityhub/SeverityLabel": "MEDIUM",
    "aws/securityhub/ProductName": "GuardDuty",
    "aws/securityhub/CompanyName": "AWS"
  },
  "Resources": [
    {
      "Type": "AwsIamAccessKey",
      "Id": "AWS::IAM::AccessKey:GeneratedFindingAccessKeyId",
      "Partition": "aws",
      "Region": "us-east-1",
      "Details": {
        "AwsIamAccessKey": {
          "UserName": "GeneratedFindingUserName"
        }
      }
    }
  ],
  "WorkflowState": "NEW",
  "RecordState": "ACTIVE"
}
]

cloud_watch_finding = {
    "version": "0",
    "id": "CWE-event-id",
    "detail-type": "Security Hub Finding Notification",
    "source": "aws.securityhub",
    "account": "111122223333",
    "time": "2017-12-22T18:43:48Z",
    "region": "us-west-1",
    "resources": [],
    "detail": {
        "action name":"action name",
        "action description":"action description",
        "action id":"action id",
        "findings": [
            {
                "AwsAccountId": "081476508764",
                "CreatedAt": "2018-11-07T20:14:13.907Z",
                "Description": "Unusual console login seen from principal vvenkatara@paloaltonetworks.com. Login activity using this client application, from the specific location has not been seen before from this principal.",
                "FirstObservedAt": "2018-11-07T19:55:10Z",
                "GeneratorId": "arn:aws:guardduty:us-east-1:081476508764:detector/2eafe39b3fe0deb038f9063c281aa559",
                "Id": "arn:aws:guardduty:us-east-1:081476508764:detector/2eafe39b3fe0deb038f9063c281aa559/finding/98b377e7d0c9ad9b1496462bcf3de1c4",
                "LastObservedAt": "2018-11-07T19:55:10Z",
                "ProductArn": "arn:aws:overbridge:us-west-2::provider:aws/guardduty",
                "ProductFields": {
                    "action/actionType": "AWS_API_CALL",
                    "action/awsApiCallAction/api": "ConsoleLogin",
                    "action/awsApiCallAction/callerType": "Remote IP",
                    "action/awsApiCallAction/remoteIpDetails/city/cityName": "San Jose",
                    "action/awsApiCallAction/remoteIpDetails/country/countryName": "United States",
                    "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "37.3249",
                    "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "-121.9153",
                    "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "199.167.54.229",
                    "action/awsApiCallAction/remoteIpDetails/organization/asn": "396421",
                    "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "PALO ALTO NETWORKS",
                    "action/awsApiCallAction/remoteIpDetails/organization/isp": "Palo Alto Networks",
                    "action/awsApiCallAction/remoteIpDetails/organization/org": "Palo Alto Networks",
                    "action/awsApiCallAction/serviceName": "signin.amazonaws.com",
                    "additionalInfo": "{\"recentApiCalls\":[{\"api\":\"ConsoleLogin\",\"count\":1}]}",
                    "archived": "false",
                    "count": "1",
                    "detectorId": "2eafe39b3fe0deb038f9063c281aa559",
                    "resourceRole": "TARGET"
                },
                "Resources": [
                    {
                        "Details": {
                            "AwsIamAccessKey": {
                                "UserName": "vvenkatara@paloaltonetworks.com"
                            }
                        },
                        "Id": "AWS::IAM::AccessKey:null",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "Type": "AWSIAMAccessKey"
                    }
                ],
                "SchemaVersion": "2018-10-08",
                "Severity": {
                    "Normalized": 50,
                    "Product": 5
                },
                "Title": "Unusual console login was seen for principal vvenkatara@paloaltonetworks.com.",
                "Types": [
                    "Unusual Behaviors/User/UnauthorizedAccess:IAMUser-ConsoleLogin"
                ],
                "UpdatedAt": "2018-11-07T20:14:13.907Z"
            },
            {
                "AwsAccountId": "081476508764",
                "CreatedAt": "2018-11-01T18:21:29.367Z",
                "Description": "AWS CloudTrail trail arn:aws:cloudtrail:us-east-1:081476508764:trail/testing was disabled by ADMIN-evident calling StopLogging under unusual circumstances. This can be attackers attempt to cover their tracks by eliminating any trace of activity performed while they accessed your account.",
                "FirstObservedAt": "2018-11-01T18:19:28Z",
                "GeneratorId": "arn:aws:guardduty:us-east-1:081476508764:detector/2eafe39b3fe0deb038f9063c281aa559",
                "Id": "arn:aws:guardduty:us-east-1:081476508764:detector/2eafe39b3fe0deb038f9063c281aa559/finding/3eb3684120cbc7f106c3649b0441a888",
                "LastObservedAt": "2018-11-01T18:19:28Z",
                "ProductArn": "arn:aws:overbridge:us-west-2::provider:aws/guardduty",
                "ProductFields": {
                    "action/actionType": "AWS_API_CALL",
                    "action/awsApiCallAction/affectedResources/AWS::CloudTrail::Trail": "arn:aws:cloudtrail:us-east-1:081476508764:trail/testing",
                    "action/awsApiCallAction/api": "StopLogging",
                    "action/awsApiCallAction/callerType": "Remote IP",
                    "action/awsApiCallAction/remoteIpDetails/city/cityName": "Fountain Hills",
                    "action/awsApiCallAction/remoteIpDetails/country/countryName": "United States",
                    "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "33.6085",
                    "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "-111.7237",
                    "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "68.3.242.172",
                    "action/awsApiCallAction/remoteIpDetails/organization/asn": "22773",
                    "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "Cox Communications Inc.",
                    "action/awsApiCallAction/remoteIpDetails/organization/isp": "Cox Communications",
                    "action/awsApiCallAction/remoteIpDetails/organization/org": "Cox Communications",
                    "action/awsApiCallAction/serviceName": "cloudtrail.amazonaws.com",
                    "archived": "false",
                    "count": "1",
                    "detectorId": "2eafe39b3fe0deb038f9063c281aa559",
                    "resourceRole": "TARGET"
                },
                "Resources": [
                    {
                        "Details": {
                            "AwsIamAccessKey": {
                                "UserName": "ADMIN-evident"
                            }
                        },
                        "Id": "AWS::IAM::AccessKey:ASIARF6DA3ROAGQXOVR6",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "Type": "AWSIAMAccessKey"
                    }
                ],
                "SchemaVersion": "2018-10-08",
                "Severity": {
                    "Normalized": 20,
                    "Product": 2
                },
                "Title": "AWS CloudTrail trail arn:aws:cloudtrail:us-east-1:081476508764:trail/testing was disabled.",
                "Types": [
                    "TTPs/Defense Evasion/Stealth:IAMUser-CloudTrailLoggingDisabled"
                ],
                "UpdatedAt": "2018-11-01T18:21:29.367Z"
            },
            {
                "AwsAccountId": "081476508764",
                "CreatedAt": "2017-03-22T13:22:13.933Z",
                "GeneratorId": "TestDetector",
                "Id": "us-east-1/081476508764/sample-finding",
                "ProductArn": "arn:aws:overbridge:us-east-1:081476508764:provider:private/default",
                "Resources": [
                    {
                        "Id": "arn:aws:ec2:us-west-2:123456789012:instance:i-123abc",
                        "Type": "AWS::EC2::Instance"
                    }
                ],
                "SchemaVersion": "2018-10-08",
                "Severity": {
                    "Normalized": 100,
                    "Product": 10
                },
                "Types": [],
                "UpdatedAt": "2017-03-22T13:22:13.933Z"
            }
        ]
    }
}

class EnvSettings:

    def __init__(self, fw_ip, username, password,
                 untrust_zone_name, trust_zone_name, 
                 security_rule_name, rule_action,
                 sechub_dag_name, tag_for_gd_ips):
        self.fw_ip = fw_ip
        self.username = username
        self.password = password
        self.untrust_zone_name = untrust_zone_name
        self.trust_zone_name = trust_zone_name 
        self.security_rule_name = security_rule_name
        self.rule_action = rule_action
        self.sechub_dag_name = sechub_dag_name
        self.tag_for_gd_ips = tag_for_gd_ips

    def __str__(self):
        return "FW IP: {}\n"\
                "Untrust Zone: {}\n"\
                "Trust Zone: {}\n"\
                "Security Rule Name: {}\n"\
                "DAG Name: {}\n"\
                "Tag Name for DAGS: {}".format(self.fw_ip,
                self.untrust_zone_name, self.trust_zone_name, 
                self.security_rule_name, self.sechub_dag_name, 
                self.tag_for_gd_ips)

class AWSFinding:

    def __init__(self, provider, finding_ip):
        self.provider = provider
        self.finding_ip = finding_ip

    def __str__(self):
        return "Provider: {}\nIPAddress: {}".format(
            self.provider, self.finding_ip
        )

class FindingParser:

    @staticmethod
    def get_provider(provider_arn):
        match = re.search('product\/(\w+)\/(\w+)', provider_arn)
        if match:
            #print match.group(1), match.group(2)
            return match.group(2)
        else:
            print "Couldn't find a regex that matches."

    @staticmethod
    def get_findings():
        import_response = securityhub.get_findings()
        return import_response

    @staticmethod
    def extract_cw_findings(input_json):
        """
        This method is used to parse the AWS findings format and 
        then extract the salient fields from it. 
        """

        finding_details = input_json.get('detail')
        if not finding_details:
            raise Exception("Potentially malformatted finding. Unable to extract the 'detail' field")
        
        findings = finding_details.get('findings')
        if not findings:
            raise Exception("Potentially malformatted finding. Unable to extract the 'findings' field")
        
        findings_objects = []

        try:
            for finding in findings:
                #print finding
                af = FindingParser.aws_findings_parser(finding)
                findings_objects.append(af)
        except Exception, e:
            print("Exception occurred: %s", e)

        return findings_objects

    @staticmethod
    def extract_raw_findings(findings):
        """
        This method is used to parse the AWS findings format and 
        then extract the salient fields from it. 
        """
        
        findings_objects = []

        try:
            for finding in findings:
                af = FindingParser.aws_findings_parser(finding)
                findings_objects.append(af)
        except Exception, e:
            print("Exception occurred: %s", e)

        return findings_objects

    @staticmethod
    def aws_findings_parser(finding):
        """
        Extract the finding details from the information
        """
        #print json.dumps(finding, sort_keys=True, indent=4)
        product_arn = finding.get('ProductArn')
        product_fields = finding.get('ProductFields')
        ip_address = None
        
        if product_fields:
            for _k in product_fields.keys():
                if 'ipAddressV4' in _k:
                    ip_address = product_fields[_k]
                    break
        else:
            print("No IPAddress found. Nothing to do.")
            return 1
        provider = FindingParser.get_provider(product_arn)
        #print("the provider is: {}\t IPAddress is: {}".format(provider, ip_address))
        af = AWSFinding(provider, ip_address)
        return af

def sechub(findings): 
    _l = FindingParser.extract_raw_findings(findings)
    return _l

def get_vm_series_handle(env_settings):
    """
      Establish a connection and a handle to the 
      VM-Series FW. 
    """
    fw_hndl = pan_fw(env_settings.fw_ip, env_settings.username, 
                     env_settings.password, env_settings.untrust_zone_name, 
                     env_settings.trust_zone_name, env_settings.security_rule_name, 
                     env_settings.rule_action, 
                     env_settings.sechub_dag_name, env_settings.tag_for_gd_ips)

    fw_hndl.init_fw_handle()
    fw_hndl.cache_rulebase()

    return fw_hndl

def check_provider_dag(fw_hndl, provider_name):
    """
      Check to see if a DAG with the name of the 
      provider exists on the firewal. 

      Note: There will a DAG for each provider on 
            AWS Security Hub. 
    """
    if not fw_hndl.check_dag_exists(provider_name):
        return False
    else:
        return True

def add_provider_dag(fw_hndl, provider_name):
    """
      Add the DAG corresponding to the name of the 
      insights provider. 
    """
    # add the dag to the fw
    ag_object = pan_fw.create_address_group_object(address_gp_name=fw_hndl.dag_name,
                                            dynamic_value=fw_hndl.dag_tag_name,
                                            description='DAG for SecurityHub IP Mappings',
                                            tag_name=None
                                            )
    fw_hndl.add_address_group(ag_object)


def create_vm_series_sec_rule(fw_hndl):
    """
        All actions used to configure the VM-Series FW. 
    """
    if not fw_hndl.check_security_rules():
        sec_pol = fw_hndl.create_security_rule(
                rule_name=fw_hndl.security_rule_name,
                description='description',
                tag_name=[],
                source_zone=fw_hndl.untrust_zone,
                destination_zone=fw_hndl.trust_zone,
                source_ip=[fw_hndl.dag_name],
                source_user=['any'],
                destination_ip=['any'],
                category=['any'],
                application=['any'],
                service=['application-default'],
                hip_profiles=['any'],
                group_profile={},
                antivirus={},
                vulnerability={},
                spyware={},
                url_filtering={},
                file_blocking={},
                data_filtering={},
                wildfire_analysis={},
                log_start=False,
                log_end=True,
                rule_type='universal',
                action=fw_hndl.rule_action
            )
        print "security policy", sec_pol
        fw_hndl.insert_rule(sec_pol)
    else:
        print "Security rule already exists. No need to create a new rule. "

def main():
    """
     Main driver which receives the insights and findings from 
     AWS Security Hub, processes the isights and makes the
     IP addresses actionable on the Palo Alto Networks
     VM-Series firewall. 
    """

    env_obj = EnvSettings(os.environ['FW_IP'],
                        os.environ['USERNAME'],
                        os.environ['PASSWORD'],
                        os.environ['UNTRUST_ZONE'],
                        os.environ['TRUST_ZONE'],
                        os.environ['SECURITY_RULE_NAME'],
                        os.environ.get('RULE_ACTION', 'deny'),
                        os.environ.get("GD_DAG_NAME", "default_gd_dag_name"),
                        os.environ.get("FW_DAG_TAG", "AWS:GD")
    )

    # Setup the VM-Series FW accordingly
    fw_hndl = get_vm_series_handle(env_obj)

    # Process the findings results 
    get_findings_response = securityhub.get_findings()
    #print json.dumps(get_findings_response, sort_keys=True, indent=4)


    finding_objs = sechub(get_findings_response.get('Findings'))

    # The call below can be used for local testing purposes.
    #finding_objs = sechub(direct_findings)
    
    # Check to ensure that the DAG does not exist
    if not check_provider_dag(fw_hndl, env_obj.sechub_dag_name):
        add_provider_dag(fw_hndl, env_obj.sechub_dag_name)

    create_vm_series_sec_rule(fw_hndl)
    
    for finding in finding_objs:
        if not finding.finding_ip:
            print "No IP address associated with the finding"
            continue
        # register the IP to Tag mapping 
        print "Adding tag to ip mapping: {}".format(finding.finding_ip)
        fw_hndl.register_ip_to_tag_map(finding.finding_ip)

    fw_hndl.commit()


if __name__ == "__main__":
    main()