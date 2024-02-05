package main

import (
	"fmt"
	//"net"
	//"net/netip"
	"flag"
	"os"
	"strings"
)

func validCIDRFormat(cidr string) bool {
	stringParts := strings.Split(cidr, "/")

	if len(stringParts) != 2 {
		return false
	}
	return true
}

func main() {
	var ipAddr = flag.String("ip", "", "At least a single IP required")
	var CIDR = flag.String("c", "", "At least a CIDR required for scanning")
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

	if !validCIDRFormat(cidr) {
		fmt.Println("This is an invalid CIDR notation")
		os.Exit(1)
	}

	fmt.Println("The output is", ip)
}
