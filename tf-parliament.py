#!/usr/bin/env python
import argparse
import glob
import hcl2
import os
import re
import json
import parliament
from parliament.cli import is_finding_filtered
import sys

statement_template = """{{
    "Effect": "{effect}",
    "Action": {actions}
    {resources_block}
}}"""

policy_template = """{{
    "Version": "2012-10-17",
    "Id": "123",
    "Statement": {iam_statements}
}}"""

field_mappings = [
    {'tf_key': 'effect', 'iam_key': 'Effect', 'mock_value': 'Allow'},
    {'tf_key': 'actions', 'iam_key': 'Action', 'mock_value': '*'},
    {'tf_key': 'not_actions', 'iam_key': 'NotAction', 'mock_value': '*'},
    {'tf_key': 'resources', 'iam_key': 'Resource', 'mock_value': '*'},
    {'tf_key': 'not_resources', 'iam_key': 'NotResource', 'mock_value': '*'},
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


def format_finding(f):
    if isinstance(f.detail, list):
        details_formatted = []
        for d in f.detail:
            detail_formatted = ', '.join([f'{k}: {d[k]}' for k in d.keys()])
            details_formatted.append(detail_formatted)
        details_formatted = "\n  ".join(details_formatted)
    else:
        details_formatted = f.detail

    return f'{bcolors.WARNING}{f.issue}{bcolors.ENDC}\nDetails:\n  {details_formatted}\nLocation:\n  {f.location}'


def mock_iam_statement_from_tf(statement_data):
    # Create a mock IAM statement from a TF definition,
    # copying across only fields defined in the field_mappings
    # and replacing TF interpolations "${var.xxx}"
    # with mock vars for the field to pass validation
    mock_iam_statement = {}

    # In TF, effect is optional and defaults to 'Allow'
    try:
        mock_iam_statement['Effect'] = statement_data['effect']
    except KeyError:
        mock_iam_statement['Effect'] = 'Allow'

    for field in field_mappings:
        if statement_data.get(field['tf_key'], None):
            field_values = statement_data.get(field['tf_key'])[0]

            if isinstance(field_values, list):
                field_values = list(map(lambda x: re.sub('\${.*?}', field['mock_value'], x), field_values))
            else:
                field_values = re.sub('\${.*?}', field['mock_value'], field_values)

            mock_iam_statement[field['iam_key']] = field_values
    return mock_iam_statement


def validate_file(filename):
    with(open(filename, 'r')) as file:
        tf = hcl2.load(file)

    findings = []

    # Validate data.aws_iam_policy_document
    for policy_document in filter(lambda x: x.get('aws_iam_policy_document', None), tf.get('data', [])):
        iam_statements = []
        policy_name = list(policy_document['aws_iam_policy_document'].keys())[0]
        for statement_data in policy_document['aws_iam_policy_document'][policy_name]['statement']:
            # Don't check assume role policies; these will have spurious findings for
            # "Statement contains neither Resource nor NotResource"
            actions = statement_data.get('actions')[0]
            if actions == ['sts:AssumeRole'] or actions == ['sts:AssumeRoleWithSAML']:
                continue

            iam_statements.append(mock_iam_statement_from_tf(statement_data))

        policy_string = policy_template.format(iam_statements=json.dumps(iam_statements))
        findings += parliament.analyze_policy_string(policy_string).findings

    # Validate resource.aws_iam_policy
    for policy in filter(lambda x: x.get('aws_iam_policy', None), tf.get('resource', [])):
        try:
            policy_string = policy['aws_iam_policy']['policy']['policy'][0]
        except KeyError:
            continue

        findings += parliament.analyze_policy_string(policy_string).findings

    return findings


if '__main__' == __name__:
    parser = argparse.ArgumentParser()
    parser.add_argument('filename_list', nargs='+')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help="Quiet mode - only print if policy errors")
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    parser.add_argument('-c', '--config', action='store', required=False)
    parser.add_argument('--config-is-optional', action='store_true', default=False)
    args = parser.parse_args()

    # Bool to indicate if any findings, for all files - will be used for exit code
    findings_found = False

    for filename in args.filename_list:
        # If directory specified, scan all files in that dir
        if os.path.isdir(filename):
            filename = os.path.join(filename, '*')

        # Expand wildcards
        for filename in glob.glob(filename):
            # Only operate on .tf
            if not filename.endswith('.tf'):
                continue

            print("Checking {}".format(filename))
            findings = validate_file(filename)
            if args.config:
                try:
                    parliament.override_config(args.config)
                except FileNotFoundError as e:
                    if args.config_is_optional:
                        print("Config file {} not found. Ignoring.".format(args.config))
                    else:
                        raise e

            filtered_findings = []
            for finding in findings:
                finding = parliament.enhance_finding(finding)
                if not is_finding_filtered(finding):
                    filtered_findings.append(finding)
            if len(filtered_findings) > 0:
                print(f"{bcolors.FAIL}{filename}{bcolors.ENDC}")
                for f in filtered_findings:
                    print(format_finding(f))
                    findings_found = True
                print()
            elif args.verbose:
                print(f"{bcolors.OKGREEN}{filename} VALID{bcolors.ENDC}")

    # If we found any findings, in any files, exit code non-zero
    if findings_found:
        sys.exit(1)
    else:
        if not args.quiet:
            print(f"{bcolors.OKGREEN}No errors found{bcolors.ENDC}")
