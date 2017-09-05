# api-examples

These are examples of how to use the Userify API. Some of them are designed to be standalone utilities, with minimal dependencies.

Please also see:

*   https://github.com/userify/signup


# Authentication

Please create a service user that is a company admin with a very strong password (without MFA), and then create a creds file in your home directory called `.userify_creds.ini`:

    cat << EOF > ~/.userify_creds.ini

    # .userify_creds.ini 

    # The default profile if you don't specify one.
    [default]

    username=company_service_username
    password=a_really_long_password
    # optional hostname, if you're using a self-hosted edition:
    hostname=api.userify.com

    EOF



## Create User

First, list your available company ID's and choose one:

    ./create_user.py --list-companies

Example output:

    Available company IDs:
    7X6yR8EqgCt6EKCqrBBhve_company


Here's an example of how to invite the user accounts that you currently have listed in AWS IAM, using the credentials that you
already set up for AWS CLI and using your personal userify_creds.ini

    company_domain="example.com"
    company_id="7X6yR8EqgCt6EKCqrBBhve_company"

    for username in $(aws iam list-users | jq -r .Users[].UserName)
    do
        ./create_user.py \
            --email="${username}@${company_domain}" \
            --username="${username}" \
            --company_id=$company_id
    done


Copyright &copy; 2017 Userify Corporation

By purchasing, downloading, using, or installing the Userify software, you indicate that you agree to the Terms and Conditions.
