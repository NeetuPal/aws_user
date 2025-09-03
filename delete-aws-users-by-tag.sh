#!/bin/bash
# Script to delete all IAM users created by create-aws-user.sh (tagged with CreatedBy=create-aws-user-script)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}ℹ${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }

# Find users created by the create-aws-user script
print_info "Finding IAM users tagged with CreatedBy=create-aws-user-script ..."
USERS=$(aws iam list-users --query 'Users[].UserName' --output text)

for user in $USERS; do
  # Check if tag exists
  TAG_VALUE=$(aws iam list-user-tags --user-name "$user" --query "Tags[?Key=='CreatedBy'].Value" --output text)
  if [[ "$TAG_VALUE" == "create-aws-user-script" ]]; then
    print_info "Deleting user: $user"

    # 1. Delete access keys
    for key in $(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
      aws iam delete-access-key --user-name "$user" --access-key-id "$key"
      print_success "Deleted access key $key for $user"
    done

    # 2. Detach managed policies
    for policy_arn in $(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyArn' --output text); do
      aws iam detach-user-policy --user-name "$user" --policy-arn "$policy_arn"
      print_success "Detached managed policy $policy_arn for $user"
    done

    # 3. Delete inline policies
    for policy_name in $(aws iam list-user-policies --user-name "$user" --query 'PolicyNames[]' --output text); do
      aws iam delete-user-policy --user-name "$user" --policy-name "$policy_name"
      print_success "Deleted inline policy $policy_name for $user"
    done

    # 4. Delete the user
    aws iam delete-user --user-name "$user"
    print_success "User $user deleted successfully"
  fi
done

print_info "Cleanup complete."
