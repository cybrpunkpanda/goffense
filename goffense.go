package main

// Importing Packages
import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// Struct to collect scan results
type scanResults struct {
	IP       string
	portOpen bool
	Error    error
}

// Validates CIDR format and inspects for errors
func validCIDRFormat(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// Increments the IP address by one, creating a slice of IP addresses after the CIDR notation is parsed
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

// Validates IP format when input by the user
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

// Scans the SMB port on the target looking for open ports, reporting for errors if any are found
func scanSMB(ip string, port string, results chan<- scanResults) {
	addr := fmt.Sprintf("%s:%s", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)

	if err != nil {
		results <- scanResults{
			IP:       ip,
			portOpen: false,
			Error:    err,
		}
		return
	}

	defer conn.Close()
	results <- scanResults{
		IP:       ip,
		portOpen: true,
	}
}

// Authenticates to the SMB port on the target should authentication be provided via flags. Only runs if flags are provided
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

	port := "445"
	var wg sync.WaitGroup
	results := make(chan scanResults)
	var scanResultsSlice []scanResults

	go func() {
		for result := range results {
			if result.portOpen {
				fmt.Printf("SMB port is open on %s\n", result.IP)
			} else {
				fmt.Printf("SMB port is closed on %s\n", result.IP)
			}
			scanResultsSlice = append(scanResultsSlice, result)
		}
	}()

	// Sets variables as flags for input from the user
	var ipAddr = flag.String("ip", "", "A single IP with four octets is required")
	var CIDR = flag.String("c", "", "A CIDR notation is")
	var txtFile = flag.String("f", "", "A file with IP's line by line is required")
	var username = flag.String("u", "", "Username for SMB login")
	var password = flag.String("p", "", "Password for SMB login")

	flag.Parse()

	// Simplifies the variable names for use throughout the program
	ip := *ipAddr
	cidr := *CIDR
	txt := *txtFile
	usr := *username
	pass := *password

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
				wg.Add(1)
				go func(ip string) {
					defer wg.Done()
					scanSMB(ip, port, results)
				}(ip)
			}
		} else {
			fmt.Println("This is an invalid CIDR format")
			os.Exit(1)
		}
	}

	// Validates the correct format of the IP address should only one be provided
	if ip != "" {
		if validIPFormat(ip) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				scanSMB(ip, port, results)
			}()
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
				wg.Add(1)
				go func(ip string) {
					defer wg.Done()
					scanSMB(ip, port, results)
				}(ip)
			}

			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}
		} else if !fileOpenAndParse(txt) {
			os.Exit(1)
		}
	}

	// Start a goroutine to close the results channel after all other goroutines finish.
	go func() {
		wg.Wait()
		close(results)
	}()

	var loginTargets []string
	for _, result := range scanResultsSlice {
		loginTargets = append(loginTargets, result.IP)
	}

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
