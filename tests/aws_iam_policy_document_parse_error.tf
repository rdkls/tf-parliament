data "aws_iam_policy_document" "example" {
  statement {
    sid = "1"

    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
    ]

    principals {
      type = "AWS"

      identifiers = [
        "${concat(
          list(
            module.test_1.role_arn,
            module.test_2.role_arn,
            module.test_2.role_arn,
          ),
          formatlist("arn:aws:iam::${local.account}:user/%s", concat(
            list("Test1", "Test2"),
            list("Test3", "Test4"),
          ))
        )}",
      ]
    }
  }
}

resource "aws_iam_policy" "example" {
  name   = "example_policy"
  path   = "/"
  policy = "${data.aws_iam_policy_document.example.json}"
}
