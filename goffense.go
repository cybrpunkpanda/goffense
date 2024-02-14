package main

// Importing Packages
import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

// Validates CIDR format for input and parsing
func validCIDRFormat(cidr string) bool {
	cidrParts := strings.Split(cidr, "/")

	if len(cidrParts) != 2 {
		return false
	}
	return true
}

// Validates IP format for input and parsing
func validIPFormat(ip string) bool {
	stringParts := strings.Split(ip, ".")

	if len(stringParts) != 4 {
		return false
	}
	return true
}

// Opens file, scans for valid line by line strings and parses them for scanning
func fileOpenAndParse(txt string) {
	userFile, err := os.Open(txt)

	if err != nil {
		log.Fatal(err)
	}
	defer userFile.Close()

	parseFile := bufio.NewScanner(userFile)

	for parseFile.Scan() {
		lineTxt := parseFile.Text()

		fmt.Println(lineTxt)
	}
}

func scanSMB() {

}

func main() {
	// Sets variables as flags for input from the user
	var ipAddr = flag.String("ip", "", "A single IP with four octets is required")
	var CIDR = flag.String("c", "", "A CIDR notation is")
	var txtFile = flag.String("f", "", "A file with IP's line by line is required")

	flag.Parse()

	// Simplifies the variable names for use throughout the program
	ip := *ipAddr
	cidr := *CIDR
	txt := *txtFile

	// Does checks to make sure at least one of the three required flags is input
	if ip == "" && cidr == "" && txt == "" {
		fmt.Println("A target is required via -ip, -c, or -f")
		flag.Usage()
		os.Exit(1)
	}

	// This block validates the formatting of the provided target flags provided by the user
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
