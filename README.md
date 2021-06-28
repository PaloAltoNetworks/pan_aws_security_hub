This Repository will be Archive. This repository will be deleted in 10 days from 6/28/21 since we have a new Repository which addresses the same use case. Please use following Repository  PaloAltoNetworks/aws_security_hub moving forward. 





# pan_aws_security_hub
This implementation integrates the AWS Security Hub insights and makes it actionable on the VM-Series FW.

# Theory of Operation

The ```pan_aws_security_hub``` python script upon invocation does the following:

- interacts with AWS Security Hub and sources indicators of compromise. 
- processes the indicators of compromise and extracts details such as IP and some metadata. 
- interacts with the firewall to:
    -  create a dynamic address group
    -  create security rule and associates the dynamic address group with the security rule 
    -  as new IOC's are detected the IP's are registered with the tag which is used in the DAG

# Setup

## Setup AWS Credentials

   Configure the AWS credentials using one of the options described in 
   ```https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/setup-credentials.html```

## Install pandevice 

    1a. pip install pandevice

    or 

    1b. If you have virtualenvwrapper installed::
        (For more information of virtualenvs please refer to: 
        ```https://www.bogotobogo.com/python/python_virtualenv_virtualenvwrapper.php```)


    $ mkvirtualenv pandevice
    $ pip install pandevice

    Pip will install the pan-python_ library as a dependency.

    Upgrade to the latest version::

    pip install --upgrade pandevice

## Install boto3

    2a. pip install boto3

    2b. Or install boto3 into the virtual environment as done if you followed 1b.

## Setup the Environment variables 

    Cut and paste the following commands into your terminal to export these environment variables. 
    (Note: do not put it into a bash or shell script as that will not set the environment variables for your shell session.)

    Values show below are representative. Please change these to match your specific configuration. Please see 
    the description for these variables provided in the section below.

    + export FW_IP=192.168.55.10
    + export USERNAME='admin'
    + export PASSWORD='paloalto'
    + export UNTRUST_ZONE='L3-untrust'
    + export TRUST_ZONE='L3-trust'
    + export SECURITY_RULE_NAME='securityhub'
    + export RULE_ACTION='deny'
    + export GD_DAG_NAME='securitydag'
    + export FW_DAG_TAG='protect'


## Description of the environment variables 

    + FW_IP: IP Address to communicate with the firewall
    + USERNAME: Username to authenticate with the firewall
    + PASSWORD: Password used for authentication
    + UNTRUST_ZONE: The name of the untrust zone as configured on the firewall
    + TRUST_ZONE: The name of the trust zone as configured on the firewall
    + SECURITY_RULE_NAME: A name for the security rule which will be created to enforce the findings from AWS Security Hub. 
    + RULE_ACTION: A valid value for the action to be taken on a security rule match. The suggested value is 'deny'
    + GD_DAG_NAME: A name for the Dynamic Address Group to create on the firewall, which will be associated with the security rule. 
    + FW_DAG_TAG: A name for a tag which will be used to register IP's with. 


# Invocation 


Prompt> ./pan_aws_security_hub.py
   
