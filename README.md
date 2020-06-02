# Terraform Parliament -  Run [Parliament AWS IAM Checker](https://github.com/duo-labs/parliament) on Terraform Files

Parliament checks IAM policy validity against the latest [AWS IAM specifications](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html), so e.g. It'll pick up if your policy uses an older Action like `billing:*`, instead of the current `aws-portal:*`

By default, Parliament runs only on JSON IAM policies, not Terraform files. However I wanted to validate my Terraform files.

This utility parses your Terraform, finds `aws_iam_policy_document` elements, generates resulting IAM policy document strings, and runs Parliament on them.

It stubs any Terraform interpolations `${...}` so  they can be evaluated by Parliament as valid JSON.

![Example run](/doc/img/parliament-test-run.png)

## Terraform Resource Support

Resource Type | Supported?
-|-
`aws_iam_policy` | **Yes**  only inline policy not file()
`aws_iam_policy_document` | **Yes**
`aws_iam_user_policy` | No
`aws_iam_group_policy` | No
`aws_iam_role_policy` | No
`aws_s3_bucket_policy` | No
`aws_[ecr\|efs\|iot\|media_store_container\|organizations]*_policy` | No
`data.template_file` | No

The unsupported resource types should be pretty easy to add, if anyone feels a PR coming on :)

## Issues

- Sometimes the interpolation stubbing (e.g. "Replace all ${...} in a Resource with *") results in invalid values; needs to be more sophisticated than current regex replace
- No unit tests :(
- Currently not fit to be used as a GitHub action (as was my plan) since --recursive not yet implemented
- You will receive `RESOURCE_MISMATCH` if you have a policy with action `Get*` and resource ending in `/*` (referring to objects in a bucket), since `s3:Get*` includes some permissions which are bucket-level, not object-level. I have tried allowing you to ignore this by implementing config override per [Parliament doco](https://github.com/duo-labs/parliament#custom-config-file), and calling [parliament.override_config()](https://github.com/duo-labs/parliament/blob/master/parliament/cli.py#L327), to no avail
- aws_iam_policy is supported, but only inline policy; not file()
- [data.template_file](https://learn.hashicorp.com/terraform/aws/iam-policy#template_file-data-source) not supported

## Usage

### Docker

[DockerHub Repo](https://hub.docker.com/repository/docker/rdkls/tf-parliament)

Use `/github/workspace/` to mount the directory containing the Terraform, since this image is intended to run as a GitHub action:

Intention|Command
-|-
Run on the entire directory|`docker run --rm -ti -v (pwd):/github/workspace/ rdkls/tf-parliament`
Run on one file|`docker run --rm -ti -v (pwd):/github/workspace/ rdkls/tf-parliament iam.tf`
Run on some TF files only|`docker run --rm -ti -v (pwd):/github/workspace/ rdkls/tf-parliament 'iam-*.tf'`

Notes
- These examples use fish shell `(pwd)`, in bash switch that to ``` `pwd` ```
- Quotes around the argument in the last example, to avoid your shell expanding the wildcard before passing to docker.

### Native

`pip install -r requirements.txt`

`tf-parliament.py my-template.tf`

(also supports wildcards & directories per Docker method)

## Requirements

- Docker
- Terraform Files v0.12+ (though v0.11 should work too)
