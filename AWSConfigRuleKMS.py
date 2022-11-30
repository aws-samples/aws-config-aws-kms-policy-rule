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


# USE AS IS
# Helper function to check if rule parameters exist
def parameters_exist(parameters):
    return len(parameters) != 0


# Helper function used to validate input
def check_defined(reference, referenceName):
    if not reference:
        raise Exception("Error: ", referenceName, "is not defined")
    return reference


# Check whether the message is OversizedConfigurationItemChangeNotification or not
def is_oversized_changed_notification(messageType):
    check_defined(messageType, "messageType")
    return messageType == "OversizedConfigurationItemChangeNotification"


# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(messageType):
    check_defined(messageType, "messageType")
    return messageType == "ScheduledNotification"


# Get configurationItem using getResourceConfigHistory API
# in case of OversizedConfigurationItemChangeNotification
def get_configuration(resourceType, resourceId, configurationCaptureTime):
    result = AWS_CONFIG_CLIENT.get_resource_config_history(
        resourceType=resourceType,
        resourceId=resourceId,
        laterTime=configurationCaptureTime,
        limit=1,
    )
    configurationItem = result["configurationItems"][0]
    return convert_api_configuration(configurationItem)


# Convert from the API model to the original invocation model
def convert_api_configuration(configurationItem):
    for k, v in configurationItem.items():
        if isinstance(v, datetime.datetime):
            configurationItem[k] = str(v)
    configurationItem["awsAccountId"] = configurationItem["accountId"]
    configurationItem["ARN"] = configurationItem["arn"]
    configurationItem["configurationStateMd5Hash"] = configurationItem[
        "configurationItemMD5Hash"
    ]
    configurationItem["configurationItemVersion"] = configurationItem["version"]
    configurationItem["configuration"] = json.loads(configurationItem["configuration"])
    if "relationships" in configurationItem:
        for i in range(len(configurationItem["relationships"])):
            configurationItem["relationships"][i]["name"] = configurationItem[
                "relationships"
            ][i]["relationshipName"]
    return configurationItem


# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistiry API in getConfiguration function.
def get_configuration_item(invokingEvent):
    check_defined(invokingEvent, "invokingEvent")
    if is_oversized_changed_notification(invokingEvent["messageType"]):
        configurationItemSummary = check_defined(
            invokingEvent["configurationItemSummary"], "configurationItemSummary"
        )
        return get_configuration(
            configurationItemSummary["resourceType"],
            configurationItemSummary["resourceId"],
            configurationItemSummary["configurationItemCaptureTime"],
        )
    elif is_scheduled_notification(invokingEvent["messageType"]):
        return None
    return check_defined(invokingEvent["configurationItem"], "configurationItem")


# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configurationItem, event):
    check_defined(configurationItem, "configurationItem")
    check_defined(event, "event")
    status = configurationItem["configurationItemStatus"]
    eventLeftScope = event["eventLeftScope"]
    if status == "ResourceDeleted":
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")
    return (status == "OK" or status == "ResourceDiscovered") and not eventLeftScope


# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event=None):
    if not event:
        return boto3.client(service)
    credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(
        service,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_assume_role_credentials(role_arn):
    sts_client = boto3.client("sts")
    try:
        assume_role_response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="configLambdaExecution"
        )
        return assume_role_response["Credentials"]
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"][
                "Message"
            ] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


# This generate an evaluation for config
def build_evaluation(
    resource_id,
    compliance_type,
    event,
    resource_type=DEFAULT_RESOURCE_TYPE,
    annotation=None,
):
    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = annotation
    eval_cc['ComplianceResourceType'] = resource_type
    eval_cc['ComplianceResourceId'] = resource_id
    eval_cc['ComplianceType'] = compliance_type
    eval_cc['OrderingTimestamp'] = str(
        json.loads(event['invokingEvent'])['notificationCreationTime']
    )
    return eval_cc


def build_evaluation_from_config_item(
    configuration_item, compliance_type, annotation=None
):
    # print(configuration_item)
    # print(compliance_type)
    eval_ci = {}
    if annotation:
        eval_ci["Annotation"] = annotation
    eval_ci["ComplianceResourceType"] = configuration_item['resourceType']
    eval_ci["ComplianceResourceId"] = configuration_item['resourceId']
    eval_ci["ComplianceType"] = compliance_type
    eval_ci["OrderingTimestamp"] = configuration_item["configurationItemCaptureTime"]
    return eval_ci


# This decorates the lambda_handler in rule_code with the actual PutEvaluation call
def lambda_handler(event, context):
    # print(json.dumps(event))
    global AWS_CONFIG_CLIENT
    if ASSUME_ROLE_MODE:
        AWS_CONFIG_CLIENT = get_client("config", event)

    evaluations = []

    # print(event)
    check_defined(event, "event")
    invokingEvent = json.loads(event["invokingEvent"])
    rule_parameters = {}
    if "ruleParameters" in event:
        rule_parameters = json.loads(event["ruleParameters"])

    configuration_item = get_configuration_item(invokingEvent)

    compliance_result = evaluate_compliance(event, configuration_item, rule_parameters)
    # print(compliance_result)
    # print(type(compliance_result))

    if isinstance(compliance_result, str):
        if configuration_item:
            evaluations.append(
                build_evaluation_from_config_item(configuration_item, compliance_result)
            )
        else:
            evaluations.append(
                build_evaluation(
                    event['accountId'],
                    compliance_result,
                    event,
                    resource_type=DEFAULT_RESOURCE_TYPE,
                )
            )
    elif isinstance(compliance_result, list):
        for evaluation in compliance_result:
            missing_fields = False
            for field in (
                "ComplianceResourceType",
                "ComplianceResourceId",
                "ComplianceType",
                "OrderingTimestamp",
            ):
                if field not in evaluation:
                    print("Missing " + field + " from custom evaluation.")
                    missing_fields = True

            if not missing_fields:
                evaluations.append(evaluation)
    elif isinstance(compliance_result, dict):
        missing_fields = False
        for field in (
            "ComplianceResourceType",
            "ComplianceResourceId",
            "ComplianceType",
            "OrderingTimestamp",
        ):
            if field not in compliance_result:
                print("Missing " + field + " from custom evaluation.")
                missing_fields = True
        if not missing_fields:
            evaluations.append(compliance_result)
    else:
        evaluations.append(
            build_evaluation_from_config_item(configuration_item, "NOT_APPLICABLE")
        )

    # Put together the request that reports the evaluation status
    resultToken = event["resultToken"]
    testMode = False
    if resultToken == "TESTMODE":
        # Used solely for RDK test to skip actual put_evaluation API call
        testMode = True
    # Invoke the Config API to report the result of the evaluation
    AWS_CONFIG_CLIENT.put_evaluations(
        Evaluations=evaluations, ResultToken=resultToken, TestMode=testMode
    )
    # Used solely for RDK test to be able to test Lambda function
    return evaluations
