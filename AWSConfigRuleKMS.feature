# Rule Name:
# KMS-Least-Privilege
#
#
# Description:
# Checks that KMS Key policies adhere to least privilege
#
#
# Trigger: Periodic
#
#
# Reports on:
# AWS::KMS::Key
#
#
# Rule Parameters:
# | ------------------- | --------- | ---------|--------------------------------------------------------- |
# | Parameter Name      | Type      | Required | Description                                              |
# | ------------------- | --------- | ---------| -------------------------------------------------------- |
# | CMK_Id              | text      |    No    | Comma separated list of KMS keys that are not subject to |
# |                     |           |          | this control                                             |
# | ------------------- | --------- | ---------| -------------------------------------------------------- |
# | Admin_User_Id       | text      |    Yes   | Comma separated list of UserIds that are not subject to |
# |                     |           |          | this control                                             |
# | ------------------- | --------- | -------- | -------------------------------------------------------- |
#
#
#
Feature:
  In order to: ensure CMK KMS policies are used correctly
  As: a Security Officer
  I want: To enforce that all CMK KMS policies follow least privilege

Scenarios:

  Scenario 1: disabled-cmk-not-applicable
  Given: A CMK KMS key is not enabled
  Then: Return NOT_APPLICABLE


  Scenario 2: whitelisted-cmk-compliant
  Given: A CMK KMS key is enabled
  And: the CMK KMS key is in the list of whitelisted KMS keys
  Then: Return COMPLIANT


  Scenario 3: wildcard-policy-action-not-compliant
  Given: A CMK KMS key is enabled
  And: the CMK KMS key is not in the list of whitelisted KMS keys
  And: action is "kms:*"
  Then: Return NON_COMPLIANT


  Scenario 4: no-separation-of-duty-not-compliant
  Given: A CMK KMS key is enabled
  And: the CMK KMS key is not in the list of whitelisted KMS keys
  And: action is not "kms:*"
  And: action is "kms:Encrypt" or "kms:Decrypt"
  And: there are actions ["kms:Create*", "kms:Delete*", "kms:Put*"]
  And: Effect is allow
  And: conditions specified as
          "Condition": {
                "StringLike": {
                    "aws:userId": [...]
  Then: Return NON_COMPLIANT


  Scenario 5: separation-of-duty-compliant
  Given: A CMK KMS key is enabled
  And: the CMK KMS key is not in the list of whitelisted KMS keys
  And: action is not "kms:*"
  And: action is "kms:Encrypt" or "kms:Decrypt"
  And: there are no actions ["kms:Create*", "kms:Delete*", "kms:Put*"]
  And: Effect is allow
  And: conditions specified as
          "Condition": {
                "StringLike": {
                    "aws:userId": [...]
  Then: Return COMPLIANT


  Scenario 6: admin-actions-compliant
  Given: A CMK KMS key is enabled
  And: the CMK KMS key is not in the list of whitelisted KMS keys
  And: action is not "kms:*"
  And: conditions specified as
          "Condition": {
                "StringLike": {
                    "aws:userId": [...]
  And: userId is in the list of Admin_Role_Id
  And: actions are ["kms:Create*", "kms:Delete*", "kms:Put*"]
  And: action is not "kms:Encrypt" or "kms:Decrypt"
  And: Effect is allow
  Then: Return COMPLIANT


  Scenario 7: admin-role-not-in-whitelist-not-compliant
  Given: A CMK KMS key is enabled
  And: the CMK KMS key is not in the list of whitelisted KMS keys
  And: action is not "kms:*"
  And: conditions specified as
          "Condition": {
                "StringLike": {
                    "aws:userId": [...]
  And: userId is not in the list of Admin_Role_Id
  And: actions are ["kms:Create*", "kms:Delete*", "kms:Put*"]
  And: action is not "kms:Encrypt" or "kms:Decrypt"
  And: Effect is allow
  Then: Return NON_COMPLIANT


  Scenario 8: admin-role-not-allowed-actions-not-compliant
  Given: A CMK KMS key is enabled
  And: the CMK KMS key is not in the list of whitelisted KMS keys
  And: action is not "kms:*"
  And: conditions specified as
          "Condition": {
                "StringLike": {
                    "aws:userId": [...]
  And: userId is in the list of Admin_Role_Id
  And: actions are ["kms:Create*", "kms:Delete*", "kms:Put*"]
  And: action are "kms:Encrypt" or "kms:Decrypt"
  And: Effect is allow
  Then: Return NON_COMPLIANT
