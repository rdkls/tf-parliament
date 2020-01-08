#!/usr/bin/env python
import argparse
import glob
import hcl2
import os
import re
import json
import parliament
import sys

parser = argparse.ArgumentParser()
parser.add_argument('filename_list', nargs='+')
parser.add_argument('-q', '--quiet', action='store_true', default=False, help="Quiet mode - only print if policy errors")
args = parser.parse_args()

statement_template = """{{
    "Effect": "{effect}",
    "Action": {actions}
    {resources_block}
}}"""

policy_template = """{{
    "Version": "2012-10-17",
    "Id": "123",
    "Statement": {statements}
}}"""

field_mappings = [
    {'tf_key': 'effect', 'iam_key': 'Effect', 'mock_var': 'Allow'},
    {'tf_key': 'actions', 'iam_key': 'Action', 'mock_var': '*'},
    {'tf_key': 'not_actions', 'iam_key': 'NotAction', 'mock_var': '*'},
    {'tf_key': 'resources', 'iam_key': 'Resource', 'mock_var': '*'},
    {'tf_key': 'not_resources', 'iam_key': 'NotResource', 'mock_var': '*'},
]


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


findings_found = False


def format_finding(f):
    return f'{bcolors.WARNING}{f.issue}{bcolors.ENDC} - {f.detail} - {f.location}'


for filename in args.filename_list:
    # If directory specified, scan all files in that dir
    if os.path.isdir(filename):
        filename = os.path.join(filename, '*')

    # Expand wildcards
    for filename in glob.glob(filename):
        # Only operate on .tf
        if not filename.endswith('.tf'):
            continue

        with(open(filename, 'r')) as file:
            tf = hcl2.load(file)

        findings = []
        for policy_data in filter(lambda x: x.get('aws_iam_policy_document', None), tf.get('data', [])):
            statements = []
            policy_name = list(policy_data['aws_iam_policy_document'].keys())[0]
            for statement_data in policy_data['aws_iam_policy_document'][policy_name]['statement']:
                # Don't check assume role policies; these will have spurious findings for
                # "Statement contains neither Resource nor NotResource"
                if statement_data.get('actions')[0] == ['sts:AssumeRole']:
                    continue

                statement = {}

                for field in field_mappings:
                    if statement_data.get(field['tf_key'], None):
                        field_values = statement_data.get(field['tf_key'])[0]

                        # If there are TF vars in the string e.g. "${var.xxx}"
                        # we replace these with "mock" vars for the field to pass validation
                        if list == type(field_values):
                            field_values = list(map(lambda x: re.sub('\${.*?}', field['mock_var'], x), field_values))
                        else:
                            field_values = re.sub('\${.*?}', field['mock_var'], field_values)

                        statement[field['iam_key']] = field_values

                statements.append(statement)

            policy_string = policy_template.format(statements=json.dumps(statements))
            analyzed_policy = parliament.analyze_policy_string(policy_string)

            if analyzed_policy.findings:
                findings += analyzed_policy.findings
                
        if findings:
            print(f"{bcolors.FAIL}{filename}{bcolors.ENDC}")
            for f in findings:
                print(format_finding(f))
                findings_found = True
            print()

if findings_found:
    sys.exit(1)
else:
    if not args.quiet:
        print(f"{bcolors.OKGREEN}No errors found{bcolors.ENDC}")
