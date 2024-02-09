package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func validCIDRFormat(cidr string) bool {
	cidrParts := strings.Split(cidr, "/")

	if len(cidrParts) != 2 {
		return false
	}
	return true
}

func validIPFormat(ip string) bool {
	stringParts := strings.Split(ip, ".")

	if len(stringParts) != 4 {
		return false
	}
	return true
}

func fileOpenAndParse(txt string) {

}

func scanSMB() {

}

func main() {
	var ipAddr = flag.String("ip", "", "A single IP with four octets is required")
	var CIDR = flag.String("c", "", "A CIDR notation is")
	var txtFile = flag.String("f", "", "A file with IP's line by line is required")

	flag.Parse()

	ip := *ipAddr
	cidr := *CIDR
	txt := *txtFile

	if ip == "" && cidr == "" && txt == "" {
		fmt.Println("A target is required via -ip, -c, or -f")
		flag.Usage()
		os.Exit(1)
	}

	if cidr != "" && !validCIDRFormat(cidr) {
		fmt.Println("The CIDR format is incorrect.")
		os.Exit(1)
	}

	if ip != "" && !validIPFormat(ip) {
		fmt.Println("The IP format is incorrect")
		os.Exit(1)
	}

	fmt.Println("The output is", ip)
}
