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

	// "errors"

	"github.com/hirochachacha/go-smb2"
)

// Struct to collect scan results
type ScanResults struct {
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
func scanSMB(ip string, port string, results chan<- ScanResults) {
	addr := fmt.Sprintf("%v:%v", ip, port)
	conn, err := net.Dial("tcp", addr)

	if err != nil {
		results <- ScanResults{
			IP:       ip,
			portOpen: false,
		}

		return
	}
	conn.Close()
	results <- ScanResults{
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
			defer c.Logoff()
			fmt.Printf("Successfully authenticated to %s\n", loginAttempt)
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

	ports := []string{"445", "139"}
	var wg sync.WaitGroup
	results := make(chan ScanResults)

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
		if !validCIDRFormat(cidr) {
			fmt.Println("This is an invalid CIDR format")
			os.Exit(1)
		} else {
			ip, ipNet, _ := net.ParseCIDR(cidr)
			cidrSlice := []string{}
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); ip = incIP(ip) {
				cidrSlice = append(cidrSlice, ip.String())
			}

			fmt.Println("Scanning CIDR range: ", cidr)

			for _, ip := range cidrSlice {

				for _, port := range ports {
					wg.Add(1)
					go func(ip string, port string) {
						defer wg.Done()
						c := make(chan struct{})
						go func() {
							defer close(c)
							scanSMB(ip, port, results)
						}()
						select {
						case <-c:
							// scanSMB finished
						case <-time.After(time.Second * 5):
							// scanSMB didn't finish in 5 seconds
							fmt.Println("Scan timed out for port: ", port, " on IP: ", ip)
						}
					}(ip, port)
				}
			}
		} // <-- Missing curly bracket was here
		for result := range results {
			fmt.Println(result)
		}
	}
	// Validates the correct format of the IP address should only one be provided
	if ip != "" {
		if !validIPFormat(ip) {
			fmt.Println("This is an invalid IP format")
			os.Exit(1)
		} else {
			fmt.Println("Scanning IP address: ", ip)
			for _, port := range ports {
				wg.Add(1)
				go func(port string) {
					defer wg.Done()
					c := make(chan struct{})
					go func() {
						defer close(c)
						scanSMB(ip, port, results)
					}()
					select {
					case <-c:
						// scanSMB finished
					case <-time.After(time.Second * 5):
						// scanSMB didn't finish in 5 seconds
						fmt.Println("Scan timed out for port: ", port, " on IP: ", ip)
					}
				}(port)
			}
		}
	}

	for i := 0; i < len(ports); i++ {
		fmt.Println(<-results)
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
					for _, port := range ports {
						scanSMB(ip, port, results)
					}
				}(ip)
			}

			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}
		} else if !fileOpenAndParse(txt) {
			os.Exit(1)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collects the results of the scan and prints them to the console
	loginTargets := []string{}

	for result := range results {
		fmt.Println(result)
		if result.portOpen {
			loginTargets = append(loginTargets, result.IP)
		}
	}
	// Define loginTargets slice to collect IPs with open ports
	if usr != "" && pass != "" {
		var authChoice string
		fmt.Println("Would you like to attempt to authenticate to the SMB port? (y/n)")
		fmt.Scanln(&authChoice)

		if authChoice == "y" {
			for entries := range results {
				if entries.portOpen {
					fmt.Printf("IP: %s Port: %s is open\n", entries.IP, ports)
					loginTargets = append(loginTargets, entries.IP)
				}
			}
			authSMB(loginTargets, usr, pass)

		} else {
			fmt.Printf("Authentication has failed for \n %s", loginTargets)
		}
	}
}
