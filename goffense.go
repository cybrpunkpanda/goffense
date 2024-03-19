package main

// Importing Packages
import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// Validates CIDR format for input and parsing
func validCIDRFormat(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr) //Each _ is an omission of the output of net.ParseCIDR
	return err == nil
}

// Increments the IP address by one, creating a slice of IP addresses after the CIDR is parsed
func incIP(ip net.IP) net.IP {
	inc := make(net.IP, len(ip))
	copy(inc, ip)
	for j := len(inc) - 1; j >= 0; j-- {
		inc[j]++
		if inc[j] > 0 {
			break
		}
	}
	return inc
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
		}
	}
	// If variable is set to true this prints
	if badIP {
		fmt.Println("One or more of the IP addresses in your list is not formatted correctly and was not have been included in the scan")
	}
	// If there is an error during the scan this if errors out
	if err := lineScan.Err(); err != nil {
		log.Fatal(err)
		return false
	}

	return true
}

// Scans the SMB port on the target
func scanSMB(target string) {
	smbPorts := []string{"445", "139"}
	for _, port := range smbPorts {
		addr := fmt.Sprintf("%s:%s", target, port)
		conn, err := net.DialTimeout("tcp", addr, time.Duration(1)*time.Second)
		if err != nil {
			fmt.Printf("SMB port closed on %s\n", target)
			return
		}
		defer conn.Close()
		fmt.Printf("SMB port open on %s at port %s\n", target, port)
	}
}

func printBanner() {
	banner := `
===========================================================================		                                                                         
______   _____   ______   ______   ______   ____   _   ______   ______  
|   ___| /     \ |   ___| |   ___| |   ___| |    \ | | |   ___| |   ___| 
|   |  | |     | |   ___| |   ___| |   ___| |     \| |  "-.-"  |   ___| 
|______| \_____/ |___|    |___|    |______| |__/\____| |______| |______| 
																	  
=========================================================================== 
======================== Created by tacitPanda ============================
	`
	fmt.Println(banner)
}

func main() {
	// Prints the banner
	printBanner()

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

	// This block validates the formatting of the provided target flags provided by the user. If the format is incorrect the program will exit. If the format is correct the program will continue to the next block of code.
	if cidr != "" {
		if validCIDRFormat(cidr) {
			ip, ipNet, _ := net.ParseCIDR(cidr)
			cidrSlice := []string{}
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); ip = incIP(ip) {
				cidrSlice = append(cidrSlice, ip.String())
			}
			for _, ip := range cidrSlice {
				scanSMB(ip)
			}
		} else {
			fmt.Println("This is an invalid CIDR format")
			os.Exit(1)
		}
	}

	// Validates the correct format of the IP address should only one be provided
	if ip != "" {
		if validIPFormat(ip) {
			scanSMB(ip)
		} else {
			fmt.Println("This is an invalid IP format")
			os.Exit(1)
		}
	}

	// Exits if the file does not exist in the current directory. Otherwise it will scan line by line in the file
	if txt != "" {
		if fileOpenAndParse(txt) {
			file, err := os.Open(txt)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				ip := scanner.Text()
				scanSMB(ip)
			}

			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}
		} else if !fileOpenAndParse(txt) {
			os.Exit(1)
		}
	}

}
