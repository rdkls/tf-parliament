resource "aws_iam_policy" "policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "bad:Describe*",
        "another_bad:Update*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
