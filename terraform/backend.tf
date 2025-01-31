terraform {
  backend "s3" {
    bucket         = "ascending-askcto-terraform-states"
    key            = "askcto/tfstate"
    region         = "us-east-1"
    # dynamodb_table = "askcto-terraform-locks"
  }
}
