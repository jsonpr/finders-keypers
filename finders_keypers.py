import re
import sys
import argparse
import boto3
import botocore
import json
from datetime import datetime
from modules.service_key_finder import find_kms_key_usage
from modules.key_policy_check import find_external_accounts

'''
This requires IAM Permissions to List Keys, Describe Keys, and relevant service permissions.  
'''
        
parser = argparse.ArgumentParser(prog='KMS Key Usage Finder')

def kms_key_arn (input_key_arn):
    if not re.match(
        r"^arn:aws:kms:(af|il|ap|ca|eu|me|sa|us|cn)-(central|north|northeast|northwest|south|southeast|southwest|east|west)-\d:\d{12}:key/[a-zA-Z0-9-]*$"
        , input_key_arn):
        sys.exit("Not a valid KMS Key ARN")

    return input_key_arn

parser.add_argument("--keyarn", type=kms_key_arn, required=True)
parser.add_argument("--profile")
parser.add_argument("--verbose", action='store_true')
parser.add_argument("--output", help='Output file name')

args = parser.parse_args()

session = boto3.Session(profile_name = args.profile)

key_resources = []
key_services = []

input_key_arn = args.keyarn

split_arn = input_key_arn.split(":")
key_region = split_arn[3]

key_resources = []
#key_services = []

try:
    find_kms_key_usage(session, key_region, input_key_arn, key_resources)
    ext_accounts = find_external_accounts(session, key_region, input_key_arn)
    if len(ext_accounts) > 0:
        print("From analyzing the key policy, there could be resources encrypted with KMS Key outside of this account.")
    print("Total Number of Resources encrypted with KMS Key Provided: " + str(len(key_resources)))

    key_index=0

    if args.verbose:
        for item in key_resources:
            print (key_resources[key_index])
            key_index = key_index + 1
    else:
        for item in key_resources:
            print (key_resources[key_index]['arn'])
            key_index = key_index + 1

    if args.output:
        output = {}

        output['metadata'] = {
                'input_key': input_key_arn,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        output['results'] = key_resources

        with open(args.output, 'w') as f:
            json.dump(output, f, indent=4)

except Exception as e:
    print(f"Error while running Key Usage Finder: {e}")
