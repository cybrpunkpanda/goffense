package main

// Importing Packages
import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	// "strings"
	"net"
)

// Validates CIDR format for input and parsing
func validCIDRFormat(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// Validates IP format for input and parsing
func validIPFormat(ip string) bool {
	return net.ParseIP(ip) != nil
}

// Opens file, scans for valid line by line strings and parses them for scanning
func fileOpenAndParse(txt string) bool {
	userFile, err := os.Open(txt)
	// If the file does not exist in the current directory it will error out the program
	if err != nil {
		log.Fatal(err)
		return false
	}
	// Ensures that, once all of the code within this function is executed, the file that was opened is closed
	defer userFile.Close()

	// Variables set for opening and scanning the file and identifying bad IP schema
	lineScan := bufio.NewScanner(userFile)
	badIP := false

	// Evaluates line by line the file
	for lineScan.Scan() {
		if !validIPFormat(lineScan.Text()) {
			fmt.Printf("Invalid IP format found: %s\n", lineScan.Text())
			badIP = true
		} else {
			fmt.Println(lineScan.Text())
		}
	}

	if badIP {
		fmt.Println("One or more of the IP addresses in your list is not formatted correctly")
	}

	if err := lineScan.Err(); err != nil {
		log.Fatal(err)
		return false
	}

	return true
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
	if cidr != ""{
		if validCIDRFormat(cidr) {
			fmt.Println("The CIDR is", cidr)
		} else {
			fmt.Println("This is an invalid CIDR format")
			os.Exit(1)
		}
	}
	
	//Validates the correct format of the IP address should only one be provided
	if ip != "" {
		if validIPFormat(ip) {
			fmt.Println("The IP is", ip)
		} else {
			fmt.Println("This is an invalid IP format")
			os.Exit(1)
		}
	}
	
	if txt != "" {
		if !fileOpenAndParse(txt) {
			os.Exit(1)
		}
	}

}
