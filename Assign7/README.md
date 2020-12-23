## DNS Blocking using iptables

AM 2013030068
### Description

This bash script provides functionality over rejecting traffic from websites using either IP or DNS.

##### Usage
```bash
Usage: ./adblock.sh  [OPTION]

Options:

  -domains	  Configure adblock rules based on the domain names of 'domainNames.txt' file.
  -ips		  Configure adblock rules based on the IP addresses of 'IPAddresses.txt' file.
  -save		  Save rules to 'adblockRules' file.
  -load		  Load rules from 'adblockRules' file.
  -list		  List current rules.
  -reset	  Reset rules to default settings (i.e. accept all).
  -help		  Display this help and exit.

```

##### Implementation

The -domains and -ips options parse domain names and IPs respectively and then 
the configured rules are written on the adblockRules file in a specific format for
the -load command.

#### Results

By testing the connections over blocked IPs, we can verify that our firewall
blocks the connections succesfully. Though, by connecting to a website which has 
an ad that we have blocked its' IP, we can see that the ad is loaded. This happens
because we do not make a direct request to connect to the IPs from which the websites
fetch the ads. 