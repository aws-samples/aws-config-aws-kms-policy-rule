# aws-config-aws-kms-policy-rule

This script snippet can be added into the skeleton RDK files downloaded to create a custom Config rule that will scan KMS CMK policies for a set of least privilege sets that you determine.

## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.

## Prerequesites

* An AWS account.
* The AWS Config (RDK) from GitHub installed.
* An IAM resource with permissions to create AWS Config rules and select an AWS Config role that allows trust policy modification.
* Have an AWS KMS customer master key (CMK) alias and role ID for whitelisting and testing configurations.
* Have Python version 3.5, 3.6, or 3.7 installed.
