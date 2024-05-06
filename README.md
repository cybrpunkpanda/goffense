# goffense #

*pronounced "go-fence"...or "gaw-fence"... I don't care as long as you know what you're referring to lol*

Offensive tooling written in Golang designed for enumeration and persistence.

## Usage ##

`go build goffense<fileType>`

`goffense <flag> <flagOptions>`

## Current Features ##
- Port scanning for SMB
  - Takes input in the form of a single IP (-ip), CIDR notation (-c), or curated list of IPs in a file (-f)
- Confirming Authentication to shares

## Features In Development ##
- Returning detailed information on open ports
  - SMB/Samba Version Details
  - Host OS Details
- Regex searching of SMB Share files for sensitive information
- File Exfiltration

## Future Developments (Wishlist) ##
- Cloud Enumeration
- Host Enumeration
- C2 Functionality
- Vulnerability Detection
- Authentic Street Taco production

