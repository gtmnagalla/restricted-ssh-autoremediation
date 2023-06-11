import boto3

def lambda_handler(event, context):
    # account id 
    ACCOUNT_ID = boto3.client('sts').get_caller_identity()['Account']
    # 'config' and 'ec2' clients 
    config_client = boto3.client('config')
    ec2_client = boto3.client('ec2')
    # config rule name that detects unrestricted incoming ssh traffic 
    ssh_rule = "restricted-ssh"
    
    #non compliant rule details
    non_compliant_detail = config_client.get_compliance_details_by_config_rule(ConfigRuleName=ssh_rule, ComplianceTypes=['NON_COMPLIANT'], Limit=100,)
    results = non_compliant_detail['EvaluationResults']
    
    #deletes security group rule with ingress ssh access
    if len(results) > 0:
        print(f"The following resource(s) are not compliant with AWS Config rule: {ssh_rule}")
        for security_group in results:
            security_group_id = security_group['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
            response = ec2_client.describe_security_groups(GroupIds=[security_group_id])
            for sg in response['SecurityGroups']:
                for ip in sg['IpPermissions']:
                    if 'FromPort' in ip and ip['FromPort']==22:
                        for cidr in ip['IpRanges']:
                            if cidr['CidrIp']=='0.0.0.0/0':
                                print(f"Revoking public access to SSH port for security group {security_group_id}")
                                ec2_client.revoke_security_group_ingress(GroupId=security_group_id, IpPermissions=[ip])