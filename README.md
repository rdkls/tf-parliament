# Terraform Parliament -  Run [Parliament AWS IAM Checker](https://github.com/duo-labs/parliament) on Terraform Files

Parliament checks IAM policy validity against the latest [AWS IAM specifications](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html), so e.g. It'll pick up if your policy uses an older Action like `billing:*`, instead of the current `aws-portal:*`

By default, Parliament runs only on JSON IAM policies, not Terraform files. However I wanted to validate my Terraform files.

This utility parses your Terraform, finds `aws_iam_policy_document` elements, generates resulting IAM policy document strings, and runs Parliament on them.

It stubs any Terraform interpolations `${...}` so  they can be evaluated by Parliament as valid JSON.

# Usage

## Docker

Use `/github/workspace/` to mount the directory containing the Terraform, since this image is intended to run as a GitHub action:

Intention|Command
-|-
Run on the entire directory|`docker run --rm -ti -v (pwd):/github/workspace/ tf-parliament:latest`
Run on one file|`docker run --rm -ti -v (pwd):/github/workspace/ tf-parliament:latest iam.tf`
Run on some TF files only|`docker run --rm -ti -v (pwd):/github/workspace/ tf-parliament:latest 'iam-*.tf'`

Note quotes around the argument in the last example, to avoid your shell expanding the wildcard before passing to docker.

## Native

`pip install -r requirements.txt`

`tf-parliament.py my-template.tf`

(also supports wildcards & directories per Docker method)

# Requirements

- Docker
- Terraform Files v0.12+
