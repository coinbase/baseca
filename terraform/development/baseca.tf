module "baseca" {
  source      = "./baseca"
  service     = "baseca"
  environment = "development"
  region      = "us-east-1"
  key_spec    = "RSA_4096"
  bucket      = "baseca-firehose-example"
}
