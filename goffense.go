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

	"github.com/hirochachacha/go-smb2"
)

// Validates CIDR format for input and parsing
func validCIDRFormat(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
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

	if err != nil {
		log.Fatal(err)
		return false
	}

	defer userFile.Close()

	lineScan := bufio.NewScanner(userFile)
	badIP := false

	for lineScan.Scan() {
		if !validIPFormat(lineScan.Text()) {
			fmt.Printf("Invalid IP format found: %s\n", lineScan.Text())
			badIP = true
		}
	}

	if badIP {
		fmt.Println("One or more of the IP addresses in your list is not formatted correctly and was not have been included in the scan")
	}

	if err := lineScan.Err(); err != nil {
		log.Fatal(err)
		return false
	}

	return true
}

// Scans the SMB port on the target
func scanSMB(target string) []string {
	smbPorts := []string{"445", "139"}
	openPorts := []string{}
	portOpen := false
	for _, port := range smbPorts {
		addr := fmt.Sprintf("%s:%s", target, port)
		conn, err := net.DialTimeout("tcp", addr, time.Duration(1)*time.Second)
		if err != nil {
			continue
		}

		defer conn.Close()
		portOpen = true

	}

	if portOpen {
		openPorts = append(openPorts, target)
	}

	return openPorts

}

// Authenticates to the SMB port on the target should authentication be provided via flags
func authSMB(loginTargets []string, usr, pass string) {

	for _, loginAttempt := range loginTargets {
		fmt.Printf("Attempting to login to %s with %s:%s\n", loginAttempt, usr, pass)
		client, err := net.Dial("tcp", fmt.Sprintf("%s:445", loginAttempt))
		if err != nil {
			fmt.Printf("Failed to authenticate to %s with error: %s\n", loginAttempt, err)
			continue
		} else {
			d := &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{
					User:     usr,
					Password: pass,
					Domain:   "",
				},
			}

			c, err := d.Dial(client)
			if err != nil {
				fmt.Printf("Failed to authenticate to %s with error: %s\n", loginAttempt, err)
				continue
			}
			fmt.Printf("Successfully authenticated to %s\n", loginAttempt)
			defer c.Logoff()
		}
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

	printBanner()

	// Sets variables as flags for input from the user
	var ipAddr = flag.String("ip", "", "A single IP with four octets is required")
	var CIDR = flag.String("c", "", "A CIDR notation is")
	var txtFile = flag.String("f", "", "A file with IP's line by line is required")
	var username = flag.String("u", "", "Username for SMB login")
	var password = flag.String("p", "", "Password for SMB login")
	//var domain = flag.String("d", "", "Domain for SMB login")

	flag.Parse()

	// Simplifies the variable names for use throughout the program
	ip := *ipAddr
	cidr := *CIDR
	txt := *txtFile
	usr := *username
	pass := *password
	//dom := *domain

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

	loginTargets := scanSMB(ip)
	fmt.Println("SMB ports are open on \n", loginTargets)

	if usr != "" && pass != "" {
		var authChoice string

		fmt.Println("Would you like to authenticate to the SMB port on the target? (y/n)")
		fmt.Scanln(&authChoice)

		if authChoice == "y" {
			authSMB(loginTargets, usr, pass)
		} else if authChoice == "n" {
			fmt.Println("Exiting...")
			os.Exit(1)
		}

	}
}
