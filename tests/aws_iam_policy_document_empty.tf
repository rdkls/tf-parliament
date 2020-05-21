data "aws_iam_policy_document" "empty" {
  source_json   = "${data.aws_iam_policy_document.source.json}"
  override_json = "${data.aws_iam_policy_document.override.json}"
}

resource "aws_iam_policy" "example" {
  name   = "example_policy"
  path   = "/"
  policy = "${data.aws_iam_policy_document.example.json}"
}
