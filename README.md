# restricted-ssh-autoremediation
disallow unrestricted incoming SSH traffic

AWS Config is used to detect inbound SSH access from the internet through the "restricted-ssh" rule. 
The Lambda function automatically remediates unauthorized SSH access by deleting the corresponding security group rule.
