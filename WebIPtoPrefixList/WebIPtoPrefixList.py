import boto3
import requests
import re 
import sys
from slack_webhook import incomingWebhook


"""Usage case "Fivetran" Download the IPs from the Fivetran https://fivetran.com/docs/getting-started/ipsand and compare them whith AWS PrefixList,
    If there is a new one, it adds it to the PL and if there is one less, it deletes it from the PL.
    "python WebIPtoPrefixList.py (DEV | PROD)"

    First you have to load the AWS user variables:        
        export AWS_ACCESS_KEY_ID=""
        export AWS_SECRET_ACCESS_KEY=""
        export AWS_SESSION_TOKEN=""
    
    It should work to get ips from any web
"""

# Confirm if the necessary variables are there
if len(sys.argv) > 2 or len(sys.argv) == 1:
    print("Usage: {} 'PROD | DEV' ".format(sys.argv[0]))
    sys.exit(1)
    
else:
	env = sys.argv[1].upper
    # You can choise use vars from CLI or add vars in to environment dictionary(line 38) and modify def main(): to get thems
	#region_name = sys.argv[2]
	#prefix_list_id = sys.argv[3]

### Slack webhook_url 
webhook_url = "https://hooks.slack.com/services/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

### WEB with IP address
# The example is for Fivetran, but it should work to get ips from any web
webtogetaddress ="https://fivetran.com/docs/getting-started/ips"


environment = {
	'PROD':{'region':'us-west-2','prefixlist':'pl-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'},
	'DEV':{'region':'us-east-1','prefixlist':'pl-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'},
}

#Can adds IP address that exists in PL but does not exist in Fivetran.(line 173)
#ExtraIPinPL = ["xxx.xxx.xxx.xxx/xx", "xxx.xxx.xxx.xxx/xx"]
ExtraIPinPL = []

class awsConnection:
    def __init__(self, region, prefix_list_id):
        self.aws = boto3.client('ec2', region_name=region)
        # maxentries: PrefixList Max entries
        self.maxentries = self.get_prefix_data(prefix_list_id)
        # prefixentries: PrefixList List of Entries
        self.prefixentries = self.get_prefix(prefix_list_id)
        self.prefix_list_id = prefix_list_id

    def get_prefix_data(self, prefix_list_id):
        #Retrive data from PL to get the Version
        response = self.aws.describe_managed_prefix_lists(
            #DryRun=True|False,
            Filters=[
                {
                    'Name': 'prefix-list-id',
                    'Values': [
                        prefix_list_id,
                    ]
                },
            ]
            #MaxResults=123,
            #NextToken='string',
            #PrefixListIds=[
            #    'string',
            #]
        )
        
        return response['PrefixLists'][0]['Version']

    def get_prefix(self,prefix_list_id):
        # Retrive PL Entries
        response = self.aws.get_managed_prefix_list_entries(PrefixListId=prefix_list_id)
        prefixes = response['Entries']
        prefixesclean = []

        for prefix in prefixes:
            cidr = prefix['Cidr']
            prefixesclean.append(cidr)
            
        # Return entries
        return prefixesclean
            
    def pl_add(self, cidrvar):
        #Add one CIDR to PrefixList
        try:
            response = self.aws.modify_managed_prefix_list(
            #DryRun=True|False,
            PrefixListId=self.prefix_list_id,
            CurrentVersion=self.maxentries,
            #PrefixListName='string',
            AddEntries=[
            {
                'Cidr': cidrvar,
                'Description': 'Fivetran'
            },
            ]
            #MaxEntries=123,
            )
            incomingWebhook(webhook_url, "The IP {} was added to the Fivetran PrefixList in {}".format(cidrvar,env))
            return response
        
        except Exception as e:
            incomingWebhook(webhook_url, "Failed to Add IP {} to Fivetran PrefixList on {}, error: {}".format(cidrvar,env,e))
            print(e)

    def pl_rm(self, cidrvar):
        #Remove one CIDR from PrefixList
        try:
            response = self.aws.modify_managed_prefix_list(
            #DryRun=True|False,
            PrefixListId=self.prefix_list_id,
            CurrentVersion=self.maxentries,
            #PrefixListName='string',
            RemoveEntries=[
            {
                'Cidr': cidrvar,
            },
            ]
            #MaxEntries=123
            )
            incomingWebhook(webhook_url, "Removed the IP {} from the Fivetran PrefixList in {}".format(cidrvar,env))            
            return response
        
        except Exception as e:
            incomingWebhook(webhook_url, "Failed to Remove IP {} to Fivetran PrefixList on {}, error: {}".format(cidrvar,env,e))
            print(e)
            


def get_fivetran_ips():
    #Download IPs from web in webtogetaddress variable
    fivetran_ips = []
    try:
        response = requests.get(webtogetaddress)    
    except:
        return False
    
    if response.status_code == 200:
        fivetran_page = response.text
        
        #Regex to match IP addresses
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}'
        
        #Filter to match Only IP addresses whit Net Mask
        for ip in re.findall(ip_pattern, response.text):
            fivetran_ips.append(ip)

    else:
        incomingWebhook(webhook_url, "Something wrong happen... when downloading Fivetran IPs")
        print("Something wrong happen... when downloading Fivetran IPs")

    return fivetran_ips


def compare_ips(fivetran_ips, IpsPrefixList):
    #Compare the PL entries with those of Fivetran
    new_ips = []
    inexistent_ips = []

    for ip in fivetran_ips:
        if ip not in IpsPrefixList:
            incomingWebhook(webhook_url, "✅ There is a new Fivetran IP: {}".format(ip))
            print("✅ There is a new Fivetran IP: {}".format(ip))
            new_ips.append(ip)
    
    for ip in IpsPrefixList:
        if ip not in fivetran_ips and ip not in ExtraIPinPL:
            incomingWebhook(webhook_url, "❌ They deleted a Fivetran IP: {}".format(ip))
            print("❌ They deleted a Fivetran IP: {}".format(ip))
            inexistent_ips.append(ip)

    for ip in inexistent_ips:
        try:
            fivetran_ips.remove(ip)
        except:
            continue
    
    for ip in new_ips:
        try:
            fivetran_ips.append(ip)
        except:
            continue

    if new_ips != [] or inexistent_ips != []:
        incomingWebhook(webhook_url, "The new baseline is: {}".format(fivetran_ips))
        print("The new baseline is: {}".format(fivetran_ips))
    else:
        incomingWebhook(webhook_url, '💡 Fivetran-change-ip: No differences found in {} :ok_con_swag:'.format(env))
        print('💡 Fivetran-change-ip: No differences found in {} :ok_con_swag:'.format(env))
    
    return new_ips, inexistent_ips


def main():
    #Get the variables from the dictionary or comment to get from the cli
    region_name = environment[env]['region']
    prefix_list_id = environment[env]['prefixlist']
    
    #Download Fivetran IPs from https://fivetran.com/docs/getting-started/ips
    IpsFivetran = get_fivetran_ips()
    
    #Connect to AWS and get PL entries
    AwsStart = awsConnection(region_name, prefix_list_id)
    
    if IpsFivetran is not False:
        #Returns new OutputIps[0] and ip that are no longer used OutputIps[1]
        OutputIps = compare_ips(IpsFivetran,AwsStart.prefixentries)
    
    if OutputIps[1]:
        for ip in OutputIps[1]:
            AwsStart.pl_rm(ip)
            incomingWebhook(webhook_url, "Removed the {} in the PL {}".format(ip, prefix_list_id))
            print("Removed the {} in the PL {}".format(ip, prefix_list_id))    
    
    if OutputIps[0]:
        for ip in OutputIps[0]:
            AwsStart.pl_add(ip)
            incomingWebhook(webhook_url, "Added the {} in the PL {}".format(ip, prefix_list_id))
            print("Added the {} in the PL {}".format(ip, prefix_list_id))
    

if __name__ == '__main__':
	main()
