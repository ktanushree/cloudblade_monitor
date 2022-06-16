# Prisma SD-WAN CloudBlade Monitor Logs
Prisma SDWAN script retrieve all the data under Monitor tab

#### Synopsis
This script retrieves all the data under Monitor tab and saves it in a CSV

#### Requirements
* Active CloudGenix Account
* Python >=3.6
* Python modules:
    * CloudGenix Python SDK >= 6.0.1b1 - <https://github.com/CloudGenix/sdk-python>

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `getcbstatus.py` 

### Usage:
Get CB Monitor Status
```
./getcbstatus.py -CN aws
```

Help Text:
```angular2
TanushreeMacBookPro:cbstatus tanushreekamath$ ./getcbstatus.py -h
usage: getcbstatus.py [-h] [--controller CONTROLLER] [--email EMAIL] [--pass PASS] [--sdkdebug SDKDEBUG] [--cloudblade CLOUDBLADE]

Get CloudBlade Monitor Status.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod: https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -P PASS  Use this Password instead of prompting

Debug:
  These options enable debugging output

  --sdkdebug SDKDEBUG, -D SDKDEBUG
                        Enable SDK Debug output, levels 0-2

Config:
  Provide CloudBlade Detail

  --cloudblade CLOUDBLADE, -CN CLOUDBLADE
                        Enter CloudBlade Name. Allowed values: aws, azure_ion, gcp, zs
(base) M-C02FRFNDMD6M:cloudblade_status tkamath$ 
TanushreeMacBookPro:cbstatus tanushreekamath$

```

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * For more information on Prisma SDWAN Python SDK, go to https://developers.cloudgenix.com
 
