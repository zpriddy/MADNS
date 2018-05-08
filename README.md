# MADNS
MADNS ( Managed Authenticated DNS )

# What is MADNS?
MADNS is an open source proof of concept for a managed authenticated DNS solution. The concept is simple.. Often times on large corporate networks the security team tries to protect the company by sinkholing known malicious domains.. The only problem is that this only works within the corporate network.. What happens when the user goes home and uses their laptops? Answer: They can still get to the malicious domains.. Obviously we can’t just make a public DNS server that anyone can check domains against.. That would give up useful threat intel...  So MADNS is here to solve that problem..

# How does MADNS work?
MADNS works by running a local DNS server on every machine.. When on the corporate network this local DNS server is bypassed.. However when off of the corporate network all DNS requests go through MADNS. MADNS only enables itself when it can reach the internet (still allowing users to get into captive portals)

MADNS takes each DNS request, checks to see if the answer is cached, and if not makes a HTTPS request to a public endpoint.. These request is authenticated with a user certificate that the endpoint checks to see if it is valid or not.. If the certificate is valid the MADNS endpoint can be configured to use an existing DNS server, or can be setup to manage DNS blackholes via a web GUI.

# Features

## Logging:
Because each user has their own certificate we can track what users, not just IPs made DNS requests

## ACLs:
You can exempt user from getting a blackhole IP for IR or approved users on the network
