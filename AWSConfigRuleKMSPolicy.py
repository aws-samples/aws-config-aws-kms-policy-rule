import boto3
import json
from urllib.parse import unquote
from fnmatch import fnmatch

class AWSConfigRuleKMSePolicy(object):
    def __init__(self, policy):
        self.dvdoc = json.loads(policy)
        # if the statement is a plain dict, force it into a list.
        statement = self.dvdoc['Statement']
        if type(statement) is dict:
            self.dvdoc['Statement'] = [statement]

    def has(self, action, resource=None):
        statements = self.dvdoc['Statement']
        matching_statements = []
        for stmt in statements:
            if stmt['Effect'] == 'Deny':
                continue
            if isinstance(stmt['Action'],str):
                if stmt['Action'].startswith(action):
                    if resource == None:
                        matching_statements.append(stmt)
                    elif isinstance(stmt['Resource'],str):
                        if stmt['Resource'].startswith(str(resource)):
                            matching_statements.append(stmt)
                    else:
                        if [x for x in stmt['Resource'] if x.startswith(str(resource))]:
                            matching_statements.append(stmt)
            else:
                if [x for x in stmt['Action'] if x.startswith(action)]:
                    if resource == None:
                        matching_statements.append(stmt)
                        continue
                    if isinstance(stmt['Resource'],str):
                        if stmt['Resource'].startswith(str(resource)):
                            matching_statements.append(stmt)
                    else:
                        if [x for x in stmt['Resource'] if x.startswith(str(resource))]:
                            matching_statements.append(stmt)
        return matching_statements

    def matches(self, action, resource=None):
        statements = self.dvdoc['Statement']
        matching_statements = []
        for stmt in statements:
            if stmt['Effect'] == 'Deny':
                continue
            if isinstance(stmt['Action'],str):
                if fnmatch(stmt['Action'],action):
                    if resource == None:
                        matching_statements.append(stmt)
                        continue
                    if isinstance(stmt['Resource'],str):
                        if fnmatch(stmt['Resource'],resource):
                            matching_statements.append(stmt)
                    else:
                        if [x for x in stmt['Resource'] if fnmatch(x, resource)]:
                            matching_statements.append(stmt)
            else:
                if [x for x in stmt['Action'] if fnmatch(x, action)]:
                    if resource == None:
                        matching_statements.append(stmt)
                        continue
                    if isinstance(stmt['Resource'],str):
                        if fnmatch(stmt['Resource'],resource):
                            matching_statements.append(stmt)
                    else:
                        if [x for x in stmt['Resource'] if fnmatch(x, resource)]:
                            matching_statements.append(stmt)
        return matching_statements
