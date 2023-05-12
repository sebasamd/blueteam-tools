# blueteam-tools
Some little scripts for automate some task related with network operations.

- WebIPtoPrefixList
    Usage case "Fivetran" Download the IPs from the Fivetran https://fivetran.com/docs/getting-started/ipsand and compare them whith AWS PrefixList,
     If there is a new one, it adds it to the PL and if there is one less, it deletes it from the PL.
     "python WebIPtoPrefixList.py (DEV | PROD)"

    First you have to load the AWS user variables:        
        export AWS_ACCESS_KEY_ID=""
        export AWS_SECRET_ACCESS_KEY=""
        export AWS_SESSION_TOKEN=""
    
    It should work to get ips from any web
