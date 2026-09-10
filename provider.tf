# Provider configuration
#
# Deliberately empty. The criblio provider reads authentication from
# environment variables (or ~/.cribl/credentials), never from Terraform
# variables — so credentials never touch this repo, tfvars, or state in
# plaintext config. See README.md "Authenticating" for exactly which
# variables to export for on-prem vs. Cribl.Cloud, and
# https://docs.cribl.io/cribl-as-code/terraform-auth/ for the full reference.
#
# On-prem (default target for this project — see var.on_prem):
#   export CRIBL_ONPREM_SERVER_URL="http://localhost:9000"
#   export CRIBL_ONPREM_USERNAME="admin"
#   export CRIBL_ONPREM_PASSWORD="admin"        # or whatever you changed it to
#
# Cribl.Cloud (if/when an API Credential is available on your org):
#   export CRIBL_CLIENT_ID="..."
#   export CRIBL_CLIENT_SECRET="..."
#   export CRIBL_ORGANIZATION_ID="..."
#   export CRIBL_WORKSPACE_ID="..."

terraform {
  required_version = ">= 1.0"

  required_providers {
    criblio = {
      source  = "criblio/criblio"
      version = ">= 1.20.138"
    }
  }
}

provider "criblio" {
}
