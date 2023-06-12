#  Lambda script that detects the "nacl-no-unrestricted-ssh-rdp" rule violation and blocks both RDP and SSH access on the associated security group

import boto3

def lambda_handler(event, context):
    # Account ID
    ACCOUNT_ID = boto3.client('sts').get_caller_identity()['Account']
    
    # Clients
    config_client = boto3.client('config')
    ec2_client = boto3.client('ec2')
    
    # Config rule name that detects unrestricted SSH or RDP traffic
    nacl_rule = "nacl-no-unrestricted-ssh-rdp"
    
    # Get non-compliant rule details
    non_compliant_detail = config_client.get_compliance_details_by_config_rule(
        ConfigRuleName=nacl_rule,
        ComplianceTypes=['NON_COMPLIANT'],
        Limit=100
    )
    results = non_compliant_detail['EvaluationResults']
    
    # Block either RDP or SSH access on security group
    if len(results) > 0:
        print(f"The following resource(s) are not compliant with AWS Config rule: {nacl_rule}")
        for security_group in results:
            security_group_id = security_group['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
            response = ec2_client.describe_security_groups(GroupIds=[security_group_id])
            for sg in response['SecurityGroups']:
                for ip in sg['IpPermissions']:
                    if ip['IpProtocol'] == 'tcp':
                        for cidr in ip('IpRanges'):
                            if cidr['CidrIp'] == '0.0.0.0/0' and (ip['FromPort'] == 22 or ip['FromPort'] == 3389):
                                print(f"Blocking {ip['FromPort']} access from 0.0.0.0/0 on security group {security_group_id}")
                                ec2_client.revoke_security_group_ingress(
                                    GroupId=security_group_id,
                                    IpPermissions=[ip]
                                )
