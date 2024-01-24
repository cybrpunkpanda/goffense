package main

import (
	"flag"
	"fmt"
)

// Setting flag options
var hostIP = flag.String("host", "123.123.123.123", "Use either a single IP or CIDR notation")

// var file = flag.String("file", "filename", "Use a file with IP addresses by line")

// func scanHost(ipAddr string) {

//}

func main() {
	flag.Parse()

	if *hostIP == "" {
		fmt.Println("Error! You must include a host using the --host flag")
	}

}
