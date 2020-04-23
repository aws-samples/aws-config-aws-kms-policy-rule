import os
import sys
import json
import datetime
import re
import boto3
import botocore
import logging
from fnmatch import fnmatch
from botocore.exceptions import ClientError
from AWSConfigRuleKMSPolicy import AWSConfigRuleKMSPolicy


LOGGING_LEVEL = logging.INFO
if None != os.getenv("LOGGING_LEVEL"):
    LOGGING_LEVEL = logging.getLevelName(os.getenv("LOGGING_LEVEL"))
logger = logging.getLogger(__name__)
logger.setLevel(LOGGING_LEVEL)
stream_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stream_handler)


##############
# Parameters #
##############

# define the default resource to report to Config Rules
AWS_CONFIG_CLIENT = boto3.client("config")
AWS_KMS_CLIENT = boto3.client("kms")
DEFAULT_RESOURCE_TYPE = "AWS::KMS::Key"


# set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account)
ASSUME_ROLE_MODE = True

# pull aliases for CMKs and pass to function below
def cmk_aliases():
    aliases = []
    response = AWS_KMS_CLIENT.list_aliases(Limit=100)
    while response['Aliases']:
        for alias in response['Aliases']:
            if 'TargetKeyId' in alias:
                aliases.append(
                    {"alias_id": alias['AliasName'], "cmk_id": alias['TargetKeyId']}
                )
        if not 'NextMarker' in response:
            return aliases
        response = AWS_KMS_CLIENT.list_aliases(Marker=response['NextMarker'], Limit=100)


# check if CMK alias is in whitelist
def cmk_alias_in_whitelist(alias_id, rule_parameters):
    try:
        alias_id = alias_id.split('/', 1)[-1]
        whitelist_param = rule_parameters["CMK_Whitelist"]
    except KeyError:
        return False
    whitelist_entries = re.split(", *", whitelist_param.strip())
    if [x for x in whitelist_entries if fnmatch(alias_id, x)]:
        return True
    else:
        return False


# check if KMS is CMK
def is_cmk(kms_id):
    metadata = AWS_KMS_CLIENT.describe_key(KeyId=kms_id)
    keyManager = metadata["KeyMetadata"]["KeyManager"]
    return keyManager == 'CUSTOMER'


# checks CMK status to determine enabled or disabled
def cmk_status(cmk_id):
    metadata = AWS_KMS_CLIENT.describe_key(KeyId=cmk_id)
    status = metadata["KeyMetadata"]["Enabled"]
    return status == False


# pulls and returns cmk policy
def get_cmk_policy(cmk_id):
    try:
        policy_response = AWS_KMS_CLIENT.get_key_policy(
            KeyId=cmk_id, PolicyName="default"
        )
        policy_content = policy_response["Policy"]

        return policy_content
    except ClientError as ce:
        logger.error = "Failure retrieving key policy for CMK {}".format(cmk_id)
        logger.exception(ce)

    return False


# check if policy has conditions with aws:userid
def if_policy_condition(policy):
    match = []
    doc = json.loads(policy)
    for statement in doc['Statement']:
        try:
            if 'aws:userId' in statement['Condition']['StringLike']:
                match.append(statement)
            return match
        except KeyError:
            continue


# pull userIds from policy condition
def get_policy_userId(policy):
    userIds = []
    doc = json.loads(policy)
    for statement in doc['Statement']:
        userId = statement['Condition']['StringLike']['aws:userId']
        if isinstance(userId, str):
            userIds.append(userId)
        else:
            for uid in userId:
                userIds.append(uid)
    return userIds


# check if whitelist admin_userid is in aws:userId
def userid_in_whitelist(userIds, rule_parameters):
    try:
        whitelist_param = rule_parameters["Admin_User_Id"]
    except KeyError:
        return False
    whitelist_entries = re.split(", *", whitelist_param.strip())
    if [x for x in whitelist_entries if any(fnmatch(p, x) for p in userIds)]:
        return True
    else:
        return False


# evaluating compliance against rule scenarios
def evaluate_compliance(event, configuration_item, rule_parameters):
    evaluations = []
    kms_aliases = cmk_aliases()
    if len(kms_aliases) > 0:
        for kms_alias in kms_aliases:
            if cmk_alias_in_whitelist(kms_alias["alias_id"], rule_parameters):
                ann = "CMK {} is in whitelist for CMK Key Policy check".format(
                    kms_alias["alias_id"]
                )
                logger.info(ann)
                ev = build_evaluation(
                    "{}".format(kms_alias["alias_id"]),
                    "COMPLIANT",
                    event,
                    annotation=ann,
                )
                evaluations.append(ev)
            # Evaluate for only cmk KMS keys
            elif is_cmk(kms_alias["cmk_id"]):
                # Evaluate if CMK key is disabled
                if cmk_status(kms_alias["cmk_id"]):
                    ann = "CMK {} is disabled".format(kms_alias["alias_id"])
                    logger.info(ann)
                    ev = build_evaluation(
                        "{}".format(kms_alias["alias_id"]),
                        "NOT_APPLICABLE",
                        event,
                        annotation=ann,
                    )
                    evaluations.append(ev)
                else:
                    cmk_policy = AWSConfigRuleKMSPolicy(get_cmk_policy(kms_alias["cmk_id"]))
                    if cmk_policy.has('kms'):
                        if cmk_policy.matches('kms:[*]'):
                            '''Match patterns are as per fnmatch'''
                            ann = "in Key Policy for {}, statement does have open KMS permissions and CMK is not whitelisted".format(
                                kms_alias["alias_id"]
                            )
                            logger.info(ann)
                            ev = build_evaluation(
                                "{}".format(kms_alias["alias_id"]),
                                "NON_COMPLIANT",
                                event,
                                annotation=ann,
                            )
                            evaluations.append(ev)
                        # check if conditions are specified in policy
                        elif if_policy_condition(get_cmk_policy(kms_alias["cmk_id"])):
                            # Using regex match to handle wildcards
                            if cmk_policy.matches("kms:Encrypt") or cmk_policy.matches(
                                "kms:Decrypt"
                            ):
                                if (
                                    cmk_policy.matches("kms:Create*")
                                    and cmk_policy.matches("kms:Delete*")
                                    and cmk_policy.matches("kms:Put*")
                                ):
                                    if userid_in_whitelist(
                                        get_policy_userId(
                                            get_cmk_policy(kms_alias["cmk_id"])
                                        ),
                                        rule_parameters,
                                    ):
                                        ann = "In Key Policy for {}, statement does not have separation of duties, CMK is not whitelisted, and user id is whitelisted".format(
                                            kms_alias["alias_id"]
                                        )
                                        logger.info(ann)
                                        ev = build_evaluation(
                                            "{}".format(kms_alias["alias_id"]),
                                            "NON_COMPLIANT",
                                            event,
                                            annotation=ann,
                                        )
                                        evaluations.append(ev)
                                    else:
                                        ann = "in Key Policy for {}, statement does not have separation of duties and CMK is not whitelisted".format(
                                            kms_alias["alias_id"]
                                        )
                                        logger.info(ann)
                                        ev = build_evaluation(
                                            "{}".format(kms_alias["alias_id"]),
                                            "NON_COMPLIANT",
                                            event,
                                            annotation=ann,
                                        )
                                        evaluations.append(ev)
                                else:
                                    ann = "in Key Policy for {}, statement does have separation of duties and CMK is not whitelisted".format(
                                        kms_alias["alias_id"]
                                    )
                                    logger.info(ann)
                                    ev = build_evaluation(
                                        "{}".format(kms_alias["alias_id"]),
                                        "COMPLIANT",
                                        event,
                                        annotation=ann,
                                    )
                                    evaluations.append(ev)
                            else:
                                # Scenarios 6/7
                                if (
                                    cmk_policy.matches("kms:Create*")
                                    and cmk_policy.matches("kms:Delete*")
                                    and cmk_policy.matches("kms:Put*")
                                ):
                                    # Scenario 6 - admin role whitelist
                                    if userid_in_whitelist(
                                        get_policy_userId(
                                            get_cmk_policy(kms_alias["cmk_id"])
                                        ),
                                        rule_parameters,
                                    ):
                                        ann = "in Key Policy for {}, statement does have separation of duties, CMK is not whitelisted, and user id is whitelisted".format(
                                            kms_alias["alias_id"]
                                        )
                                        logger.info(ann)
                                        ev = build_evaluation(
                                            "{}".format(kms_alias["alias_id"]),
                                            "COMPLIANT",
                                            event,
                                            annotation=ann,
                                        )
                                        evaluations.append(ev)
                                    # Scenario 7
                                    else:
                                        ann = "in Key Policy for {}, statement does have separation of duties, CMK is not whitelisted, and user id is not whitelisted".format(
                                            kms_alias["alias_id"]
                                        )
                                        logger.info(ann)
                                        ev = build_evaluation(
                                            "{}".format(kms_alias["alias_id"]),
                                            "NON_COMPLIANT",
                                            event,
                                            annotation=ann,
                                        )
                                        evaluations.append(ev)
                        else:
                            ann = 'Policy does not have Condition: {\"StringLike\": {\"aws:userId\": *}'
                            ev = build_evaluation(
                                "{}".format(kms_alias["alias_id"]),
                                "NON_COMPLIANT",
                                event,
                                annotation=ann,
                            )
                            evaluations.append(ev)
            else:
                ann = 'KMS is not a CMK'
                ev = build_evaluation(
                    "{}".format(kms_alias["alias_id"]),
                    'NOT_APPLICABLE',
                    event,
                    annotation=ann,
                )
                evaluations.append(ev)
    return evaluations
