locals {
  env         = coalesce(var.env, terraform.workspace)
  base_prefix = "overslash-${local.env}"
}
