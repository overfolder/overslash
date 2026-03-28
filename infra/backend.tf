terraform {
  backend "gcs" {
    bucket = "overslash-tofu-state"
    prefix = "infra"
  }
}
