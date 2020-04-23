import unittest

try:
    from unittest.mock import MagicMock, patch, ANY
except ImportError:
    import mock
    from mock import MagicMock, patch, ANY
import botocore
from botocore.exceptions import ClientError
import sys
import os
import json
import logging

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::KMS::Key'

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
KMS_CLIENT_MOCK = MagicMock()


class Boto3Mock:
    def client(self, client_name, *args, **kwargs):
        if client_name == "config":
            return CONFIG_CLIENT_MOCK
        elif client_name == "sts":
            return STS_CLIENT_MOCK
        elif client_name == "kms":
            return KMS_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")


sys.modules["boto3"] = Boto3Mock()

import AWSConfigRuleKMS as rule

class TestKMSKeyPolicy(unittest.TestCase):
    list_aliases = {
        "Aliases": [
            {
                "AliasName": "alias/testkey",
                "AliasArn": "arn:aws:kms:us-east-1:111122223333:alias/testkey",
                "TargetKeyId": "000041d6-1111-2222-3333-4444560c5555",
            }
        ]
    }

    def setUp(self):
        CONFIG_CLIENT_MOCK.reset_mock()
        KMS_CLIENT_MOCK.reset_mock()

    # scenario 1
    def test_is_not_cmk(self):
        ruleParam = (
            "{\"CMK_Whitelist\" : \"Otter*\", \"Admin_User_Id\" : \"AROAOTTER*\"}"
        )
        KMS_CLIENT_MOCK.list_aliases = MagicMock(return_value=self.list_aliases)
        KMS_CLIENT_MOCK.describe_key = MagicMock(
            return_value={
                "KeyMetadata": {
                    "KeyId": "000041d6-1111-2222-3333-4444560c5555",
                    "KeyManager": "AWS",
                }
            }
        )
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NOT_APPLICABLE', 'alias/testkey', annotation='KMS is not a CMK'
            )
        )
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_1_disabled_status(self):
        ruleParam = (
            "{\"CMK_Whitelist\" : \"Otter*\", \"Admin_User_Id\" : \"AROAOTTER*\"}"
        )
        KMS_CLIENT_MOCK.list_aliases = MagicMock(return_value=self.list_aliases)
        KMS_CLIENT_MOCK.describe_key = MagicMock(
            return_value={
                "KeyMetadata": {
                    "KeyId": "000041d6-1111-2222-3333-4444560c5555",
                    "KeyManager": "CUSTOMER",
                    "Enabled": False,
                }
            }
        )
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NOT_APPLICABLE',
                'alias/testkey',
                annotation='CMK alias/testkey is disabled',
            )
        )
        assert_successful_evaluation(self, response, resp_expected)

    # scenario 2
    def test_scenario_2_cmk_in_whitelist(self):
        ruleParam = (
            "{\"CMK_Whitelist\" : \"Otter*\", \"Admin_User_Id\" : \"AROAOTTER*\"}"
        )
        KMS_CLIENT_MOCK.list_aliases = MagicMock(
            return_value={
                "Aliases": [
                    {
                        "AliasName": "alias/Otter*",
                        "AliasArn": "arn:aws:kms:us-east-1:01234567890:alias/testkey",
                        "TargetKeyId": "000041d6-1111-2222-3333-4444560c5555",
                    }
                ]
            }
        )
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                'alias/Otter*',
                annotation='CMK alias/Otter* is in whitelist for CMK Key Policy check',
            )
        )
        assert_successful_evaluation(self, response, resp_expected)

    # scenario 3
    def test_scenario_3_kms_star_in_policy(self):
        ruleParam = (
            "{\"CMK_Whitelist\" : \"Otter*\", \"Admin_User_Id\" : \"AROAOTTER*\"}"
        )
        KMS_CLIENT_MOCK.list_aliases = MagicMock(return_value=self.list_aliases)
        KMS_CLIENT_MOCK.describe_key = MagicMock(
            return_value={
                "KeyMetadata": {
                    "KeyId": "000041d6-1111-2222-3333-4444560c5555",
                    "KeyManager": "CUSTOMER",
                    "Enabled": True,
                }
            }
        )
        policy_doc = build_policy_doc(actions="kms:*")
        policy_response = build_policy_response(policy_doc)
        KMS_CLIENT_MOCK.get_key_policy = MagicMock(return_value=policy_response)
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NON_COMPLIANT',
                'alias/testkey',
                annotation='in Key Policy for alias/testkey, statement does have open KMS permissions and CMK is not whitelisted',
            )
        )
        assert_successful_evaluation(self, response, resp_expected)

    # scenario 4
    def test_scenario_4_no_sep_of_duty(self):
        ruleParam = (
            "{\"CMK_Whitelist\" : \"Otter*\", \"Admin_User_Id\" : \"AROAOTTER*\"}"
        )
        KMS_CLIENT_MOCK.list_aliases = MagicMock(return_value=self.list_aliases)
        KMS_CLIENT_MOCK.describe_key = MagicMock(
            return_value={
                "KeyMetadata": {
                    "KeyId": "000041d6-1111-2222-3333-4444560c5555",
                    "KeyManager": "CUSTOMER",
                    "Enabled": True,
                }
            }
        )
        policy_doc = build_policy_doc(
            actions=["kms:Encrypt", "kms:Create*", "kms:Delete*", "kms:Put*"],
            userid='AIDABCDEFGHJKLMNPOQRST',
        )
        policy_response = build_policy_response(policy_doc)
        KMS_CLIENT_MOCK.get_key_policy = MagicMock(return_value=policy_response)
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NON_COMPLIANT',
                'alias/testkey',
                annotation='in Key Policy for alias/testkey, statement does not have separation of duties and CMK is not whitelisted',
            )
        )
        assert_successful_evaluation(self, response, resp_expected)

    # scenario 5
    def test_scenario_5_sep_of_duty_actions(self):
        ruleParam = (
            "{\"CMK_Whitelist\" : \"Otter*\", \"Admin_User_Id\" : \"AROAOTTER*\"}"
        )
        KMS_CLIENT_MOCK.list_aliases = MagicMock(return_value=self.list_aliases)
        KMS_CLIENT_MOCK.describe_key = MagicMock(
            return_value={
                "KeyMetadata": {
                    "KeyId": "000041d6-1111-2222-3333-4444560c5555",
                    "KeyManager": "CUSTOMER",
                    "Enabled": True,
                }
            }
        )
        policy_doc = build_policy_doc(
            actions=["kms:Decrypt"], userid='AIDABCDEFGHJKLMNPOQRST'
        )
        policy_response = build_policy_response(policy_doc)
        KMS_CLIENT_MOCK.get_key_policy = MagicMock(return_value=policy_response)
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                'alias/testkey',
                annotation='in Key Policy for alias/testkey, statement does have separation of duties and CMK is not whitelisted',
            )
        )
        assert_successful_evaluation(self, response, resp_expected)

    # scenario 6
    def test_scenario_6_admin_role_in_whitelist_sep_of_duty(self):
        ruleParam = (
            "{\"CMK_Whitelist\" : \"Otter*\", \"Admin_User_Id\" : \"AROAOTTER*\"}"
        )
        KMS_CLIENT_MOCK.list_aliases = MagicMock(return_value=self.list_aliases)
        KMS_CLIENT_MOCK.describe_key = MagicMock(
            return_value={
                "KeyMetadata": {
                    "KeyId": "000041d6-1111-2222-3333-4444560c5555",
                    "KeyManager": "CUSTOMER",
                    "Enabled": True,
                }
            }
        )
        policy_doc = build_policy_doc(
            actions=["kms:Create*", "kms:Delete*", "kms:Put*"],
            userid='AROAOTTERFGJHZSLLMNZP',
        )
        policy_response = build_policy_response(policy_doc)
        KMS_CLIENT_MOCK.get_key_policy = MagicMock(return_value=policy_response)
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                'alias/testkey',
                annotation='in Key Policy for alias/testkey, statement does have separation of duties, CMK is not whitelisted, and user id is whitelisted',
            )
        )
        assert_successful_evaluation(self, response, resp_expected)

    # scenario 7
    def test__scenario_7_admin_role_not_in_whitelist_sep_of_duty(self):
        ruleParam = (
            "{\"CMK_Whitelist\" : \"Otter*\", \"Admin_User_Id\" : \"AROAOTTER*\"}"
        )
        KMS_CLIENT_MOCK.list_aliases = MagicMock(return_value=self.list_aliases)
        KMS_CLIENT_MOCK.describe_key = MagicMock(
            return_value={
                "KeyMetadata": {
                    "KeyId": "000041d6-1111-2222-3333-4444560c5555",
                    "KeyManager": "CUSTOMER",
                    "Enabled": True,
                }
            }
        )
        policy_doc = build_policy_doc(
            actions=["kms:Create*", "kms:Delete*", "kms:Put*"],
            userid='ADAIABCDEFGHJLKMNOPQRST',
        )
        policy_response = build_policy_response(policy_doc)
        KMS_CLIENT_MOCK.get_key_policy = MagicMock(return_value=policy_response)
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NON_COMPLIANT',
                'alias/testkey',
                annotation='in Key Policy for alias/testkey, statement does have separation of duties, CMK is not whitelisted, and user id is not whitelisted',
            )
        )
        assert_successful_evaluation(self, response, resp_expected)

    # scenario 8
    def test_scenario_8_admin_role_in_whitelist_no_sep_of_duty(self):
        ruleParam = (
            "{\"CMK_Whitelist\" : \"Otter*\", \"Admin_User_Id\" : \"AROAOTTER*\"}"
        )
        KMS_CLIENT_MOCK.list_aliases = MagicMock(return_value=self.list_aliases)
        KMS_CLIENT_MOCK.describe_key = MagicMock(
            return_value={
                "KeyMetadata": {
                    "KeyId": "000041d6-1111-2222-3333-4444560c5555",
                    "KeyManager": "CUSTOMER",
                    "Enabled": True,
                }
            }
        )
        policy_doc = build_policy_doc(
            actions=["kms:Encrypt", "kms:Create*", "kms:Delete*", "kms:Put*"],
            userid='AROAOTTERFGJHZSLLMNZP',
        )
        policy_response = build_policy_response(policy_doc)
        KMS_CLIENT_MOCK.get_key_policy = MagicMock(return_value=policy_response)
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NON_COMPLIANT',
                'alias/testkey',
                annotation='In Key Policy for alias/testkey, statement does not have separation of duties, CMK is not whitelisted, and user id is whitelisted',
            )
        )
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_no_conditions(self):
        ruleParam = (
            "{\"CMK_Whitelist\" : \"Otter*\", \"Admin_User_Id\" : \"AROAOTTER*\"}"
        )
        KMS_CLIENT_MOCK.list_aliases = MagicMock(return_value=self.list_aliases)
        KMS_CLIENT_MOCK.describe_key = MagicMock(
            return_value={
                "KeyMetadata": {
                    "KeyId": "000041d6-1111-2222-3333-4444560c5555",
                    "KeyManager": "CUSTOMER",
                    "Enabled": True,
                }
            }
        )
        policy_doc = build_policy_doc(
            actions=["kms:Encrypt", "kms:Create*", "kms:Delete*", "kms:Put*"],
            has_condition=False,
        )
        policy_response = build_policy_response(policy_doc)
        KMS_CLIENT_MOCK.get_key_policy = MagicMock(return_value=policy_response)
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NON_COMPLIANT',
                'alias/testkey',
                annotation='Policy does not have Condition: {\"StringLike\": {\"aws:userId\": *}',
            )
        )
        assert_successful_evaluation(self, response, resp_expected)
