#!/bin/bash # AWS CLI script to create a user with input policy ARN or file

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if AWS CLI is installed and configured
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi

    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS CLI is not configured or credentials are invalid."
        print_info "Please run 'aws configure' first."
        exit 1
    fi

    print_success "AWS CLI is properly configured"
}

# Function to validate policy ARN format
validate_policy_arn() {
    local arn=$1
    if [[ $arn =~ ^arn:aws:iam::(aws|[0-9]{12}):policy/.+ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to validate JSON policy file
validate_policy_file() {
    local file=$1
    if [[ ! -f "$file" ]]; then
        print_error "Policy file '$file' does not exist"
        return 1
    fi

    if ! jq empty "$file" 2>/dev/null; then
        print_error "Policy file '$file' contains invalid JSON"
        return 1
    fi

    # Check if it has required policy structure
    if ! jq -e '.Version and .Statement' "$file" >/dev/null 2>&1; then
        print_error "Policy file '$file' does not have required policy structure (Version and Statement)"
        return 1
    fi

    return 0
}

# Function to create IAM user
create_iam_user() {
    local username=$1
    local path=${2:-"/"}
    
    print_info "Creating IAM user: $username"
    
    if aws iam get-user --user-name "$username" &>/dev/null; then
        print_warning "User '$username' already exists"
        read -p "Do you want to continue with existing user? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Operation cancelled"
            exit 0
        fi
    else
        aws iam create-user \
            --user-name "$username" \
            --path "$path" \
            --tags Key=CreatedBy,Value=create-aws-user-script Key=CreatedDate,Value=$(date -u +%Y-%m-%d)
        
        print_success "User '$username' created successfully"
    fi
}

# Function to attach managed policy by ARN
attach_managed_policy() {
    local username=$1
    local policy_arn=$2
    
    print_info "Attaching managed policy: $policy_arn"
    
    # Check if policy exists
    if ! aws iam get-policy --policy-arn "$policy_arn" &>/dev/null; then
        print_error "Policy '$policy_arn' does not exist or is not accessible"
        return 1
    fi
    
    # Check if policy is already attached
    if aws iam list-attached-user-policies --user-name "$username" --query "AttachedPolicies[?PolicyArn=='$policy_arn']" --output text | grep -q "$policy_arn"; then
        print_warning "Policy '$policy_arn' is already attached to user '$username'"
        return 0
    fi
    
    aws iam attach-user-policy \
        --user-name "$username" \
        --policy-arn "$policy_arn"
    
    print_success "Managed policy attached successfully"
}

# Function to create and attach inline policy from file
attach_inline_policy() {
    local username=$1
    local policy_file=$2
    local policy_name=$3
    
    print_info "Creating and attaching inline policy: $policy_name"
    
    # Check if inline policy already exists
    if aws iam get-user-policy --user-name "$username" --policy-name "$policy_name" &>/dev/null; then
        print_warning "Inline policy '$policy_name' already exists for user '$username'"
        read -p "Do you want to update it? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Skipping inline policy attachment"
            return 0
        fi
    fi
    
    aws iam put-user-policy \
        --user-name "$username" \
        --policy-name "$policy_name" \
        --policy-document file://"$policy_file"
    
    print_success "Inline policy attached successfully"
}

# Function to create access keys
create_access_keys() {
    local username=$1
    
    print_info "Creating access keys for user: $username"
    
    # Check if user already has access keys
    local existing_keys=$(aws iam list-access-keys --user-name "$username" --query 'AccessKeyMetadata[].AccessKeyId' --output text)
    
    if [[ -n "$existing_keys" ]]; then
        print_warning "User '$username' already has access keys:"
        echo "$existing_keys"
        read -p "Do you want to create additional access keys? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Skipping access key creation"
            return 0
        fi
    fi
    
    local key_output=$(aws iam create-access-key --user-name "$username" --output json)
    local access_key_id=$(echo "$key_output" | jq -r '.AccessKey.AccessKeyId')
    local secret_access_key=$(echo "$key_output" | jq -r '.AccessKey.SecretAccessKey')
    
    print_success "Access keys created successfully"
    
    # Save to file
    local credentials_file="${username}-credentials.txt"
    cat > "$credentials_file" << EOF
# AWS Credentials for user: $username
# Created: $(date)
# IMPORTANT: Store these credentials securely and delete this file after use

AWS_ACCESS_KEY_ID=$access_key_id
AWS_SECRET_ACCESS_KEY=$secret_access_key

# For AWS CLI configuration:
aws configure set aws_access_key_id $access_key_id
aws configure set aws_secret_access_key $secret_access_key

# For environment variables:
export AWS_ACCESS_KEY_ID=$access_key_id
export AWS_SECRET_ACCESS_KEY=$secret_access_key
EOF
    
    print_success "Credentials saved to: $credentials_file"
    print_warning "IMPORTANT: Store these credentials securely and delete the file after use!"
}

# Function to display user summary
display_user_summary() {
    local username=$1
    
    print_header "User Summary: $username"
    
    # User details
    echo "User Details:"
    aws iam get-user --user-name "$username" --query 'User.{UserName:UserName,UserId:UserId,Arn:Arn,CreateDate:CreateDate,Path:Path}' --output table
    
    # Attached managed policies
    echo -e "\nAttached Managed Policies:"
    local managed_policies=$(aws iam list-attached-user-policies --user-name "$username" --query 'AttachedPolicies[].{PolicyName:PolicyName,PolicyArn:PolicyArn}' --output table)
    if [[ -n "$managed_policies" && "$managed_policies" != *"None"* ]]; then
        echo "$managed_policies"
    else
        echo "No managed policies attached"
    fi
    
    # Inline policies
    echo -e "\nInline Policies:"
    local inline_policies=$(aws iam list-user-policies --user-name "$username" --query 'PolicyNames' --output table)
    if [[ -n "$inline_policies" && "$inline_policies" != *"None"* ]]; then
        echo "$inline_policies"
    else
        echo "No inline policies attached"
    fi
    
    # Access keys
    echo -e "\nAccess Keys:"
    aws iam list-access-keys --user-name "$username" --query 'AccessKeyMetadata[].{AccessKeyId:AccessKeyId,Status:Status,CreateDate:CreateDate}' --output table
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Create an AWS IAM user with policies attached.

OPTIONS:
    -u, --username USERNAME     IAM username (required)
    -p, --policy-arn ARN       AWS managed policy ARN to attach
    -f, --policy-file FILE     JSON policy file to attach as inline policy
    -n, --policy-name NAME     Name for inline policy (required with -f)
    -k, --create-keys          Create access keys for the user
    -s, --summary              Show user summary after creation
    --path PATH                IAM path for the user (default: /)
    -h, --help                 Show this help message

EXAMPLES:
    # Create user with managed policy
    $0 -u myuser -p arn:aws:iam::aws:policy/ReadOnlyAccess -k

    # Create user with custom policy file
    $0 -u myuser -f my-policy.json -n MyCustomPolicy -k

    # Create user with both managed and inline policies
    $0 -u myuser -p arn:aws:iam::aws:policy/PowerUserAccess -f custom-policy.json -n CustomPolicy -k -s

    # Interactive mode (no arguments)
    $0

EOF
}

# Interactive mode function
interactive_mode() {
    print_header "Interactive AWS User Creation"
    
    # Get username
    read -p "Enter IAM username: " USERNAME
    if [[ -z "$USERNAME" ]]; then
        print_error "Username is required"
        exit 1
    fi
    
    # Get IAM path
    read -p "Enter IAM path (default: /): " IAM_PATH
    IAM_PATH=${IAM_PATH:-"/"}
    
    # Policy selection
    echo -e "\nPolicy Options:"
    echo "1. Attach AWS managed policy (by ARN)"
    echo "2. Attach custom policy (from JSON file)"
    echo "3. Both managed and custom policies"
    echo "4. No policies (create user only)"
    
    read -p "Choose option (1-4): " POLICY_OPTION
    
    case $POLICY_OPTION in
        1|3)
            read -p "Enter AWS managed policy ARN: " POLICY_ARN
            if [[ -n "$POLICY_ARN" ]] && ! validate_policy_arn "$POLICY_ARN"; then
                print_error "Invalid policy ARN format"
                exit 1
            fi
            ;;
    esac
    
    case $POLICY_OPTION in
        2|3)
            read -p "Enter path to JSON policy file: " POLICY_FILE
            read -p "Enter name for inline policy: " POLICY_NAME
            if [[ -n "$POLICY_FILE" ]] && ! validate_policy_file "$POLICY_FILE"; then
                exit 1
            fi
            if [[ -n "$POLICY_FILE" && -z "$POLICY_NAME" ]]; then
                print_error "Policy name is required when using policy file"
                exit 1
            fi
            ;;
    esac
    
    # Access keys
    read -p "Create access keys? (y/n): " -n 1 -r CREATE_KEYS_INPUT
    echo
    CREATE_KEYS=false
    [[ $CREATE_KEYS_INPUT =~ ^[Yy]$ ]] && CREATE_KEYS=true
    
    # Summary
    read -p "Show user summary after creation? (y/n): " -n 1 -r SHOW_SUMMARY_INPUT
    echo
    SHOW_SUMMARY=false
    [[ $SHOW_SUMMARY_INPUT =~ ^[Yy]$ ]] && SHOW_SUMMARY=true
}

# Main function
main() {
    # Default values
    USERNAME=""
    POLICY_ARN=""
    POLICY_FILE=""
    POLICY_NAME=""
    CREATE_KEYS=false
    SHOW_SUMMARY=false
    IAM_PATH="/"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--username)
                USERNAME="$2"
                shift 2
                ;;
            -p|--policy-arn)
                POLICY_ARN="$2"
                shift 2
                ;;
            -f|--policy-file)
                POLICY_FILE="$2"
                shift 2
                ;;
            -n|--policy-name)
                POLICY_NAME="$2"
                shift 2
                ;;
            -k|--create-keys)
                CREATE_KEYS=true
                shift
                ;;
            -s|--summary)
                SHOW_SUMMARY=true
                shift
                ;;
            --path)
                IAM_PATH="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Check AWS CLI
    check_aws_cli
    
    # If no username provided, run interactive mode
    if [[ -z "$USERNAME" ]]; then
        interactive_mode
    fi
    
    # Validate inputs
    if [[ -z "$USERNAME" ]]; then
        print_error "Username is required"
        show_usage
        exit 1
    fi
    
    if [[ -n "$POLICY_ARN" ]] && ! validate_policy_arn "$POLICY_ARN"; then
        print_error "Invalid policy ARN format"
        exit 1
    fi
    
    if [[ -n "$POLICY_FILE" ]]; then
        if ! validate_policy_file "$POLICY_FILE"; then
            exit 1
        fi
        if [[ -z "$POLICY_NAME" ]]; then
            print_error "Policy name is required when using policy file"
            exit 1
        fi
    fi
    
    # Create user
    print_header "Creating AWS IAM User"
    create_iam_user "$USERNAME" "$IAM_PATH"
    
    # Attach managed policy if provided
    if [[ -n "$POLICY_ARN" ]]; then
        attach_managed_policy "$USERNAME" "$POLICY_ARN"
    fi
    
    # Attach inline policy if provided
    if [[ -n "$POLICY_FILE" ]]; then
        attach_inline_policy "$USERNAME" "$POLICY_FILE" "$POLICY_NAME"
    fi
    
    # Create access keys if requested
    if [[ "$CREATE_KEYS" == true ]]; then
        create_access_keys "$USERNAME"
    fi
    
    # Show summary if requested
    if [[ "$SHOW_SUMMARY" == true ]]; then
        display_user_summary "$USERNAME"
    fi
    
    print_success "User creation process completed successfully!"
    
    if [[ -n "$POLICY_ARN" || -n "$POLICY_FILE" ]]; then
        print_info "User '$USERNAME' has been created with the specified policies"
    else
        print_warning "User '$USERNAME' was created without any policies attached"
    fi
}

# Run main function with all arguments
main "$@"