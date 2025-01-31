resource "aws_ecr_repository" "askcto" {
  name                 = "askcto_${var.env}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}