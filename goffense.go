package main

import (
	"fmt"
	"net"
	"strings"

	//"regexp/syntax"
	//"time"
	//"os"
	//"errors"
	//"log"
	"flag"
	// "github.com/rclone/rclone/backend/smb"
	// "github.com/miekg/dns"
)

var ip = flag.String("host", "123.123.123.123", "Use either a single IP or CIDR notation")

func parseHostType(hostType string) {
	if strings.Contains(*ip, "/") {
		fmt.Println("This is a CIDR Notation")
	} else if net.ParseIP(*ip) == nil {
		fmt.Println("The input is not valid")
	} else {
		fmt.Println("This must be a single IP")
	}
}

func scanSMB(ipAddr string) {

}

func main() {
	flag.Parse()

	parseHostType(*ip)
}
