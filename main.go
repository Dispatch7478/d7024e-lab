// TODO: Add package documentation for `main`, like this:
// Package main something something...
package main

import (
	"d7024e/kademlia"
	"log"
	"os"
	"fmt"
	"bufio"
	"strings"
)

func main(){
	port := 8000
	bootstrapIP := os.Getenv("BOOTSTRAP_IP")

	kad, err := kademlia.NewNode(port, bootstrapIP)
	if err != nil {
		log.Fatalf("Fatal node initialization error: %v", err)
	}

	runCLI(kad)
}

func ShowBanner(kad *kademlia.Kademlia) {
	fmt.Println("==================================================")
	fmt.Printf(" Kademlia Interactive CLI - Connected Node\n")
	fmt.Printf(" ID:   %s\n", kad.Me.ID.String())
	fmt.Printf(" ADDR: %s\n", kad.Me.Address)
	fmt.Println("==================================================")
	fmt.Println(`Options:
- PING <IP:PORT>
- LOOKUP <Recipient_IP:PORT> <Target_HexID>
- RT
- EXIT
--------------------------------------------------`)
}

func runCLI(kad *kademlia.Kademlia){
	scanner := bufio.NewScanner(os.Stdin)

	ShowBanner(kad)

	for {

		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

	  input := strings.TrimSpace(scanner.Text())
	  fields := strings.Fields(input)

		if len(fields) == 0 {
			ShowBanner(kad)
    	continue
		}

	  cmd := strings.ToUpper(fields[0])

		switch cmd {
		case "EXIT":
			fmt.Printf("Thank you for using this kademlia interactive CLI!")
			os.Stdin.Close()
			return

		// Pinging node A from node B 
		case "PING":
			if len(fields) != 2 {
				fmt.Printf("Error Ping requires exactly one argument: IP:PORT")
				continue 
			}
			ip, port, ok := strings.Cut(fields[1], ":")
			if !ok || port == "" || ip == ""{
				fmt.Printf("Error: Invalid format, expected IP:PORT")
				continue 
			}
			targetAddr := fmt.Sprintf("%s:%s", ip, port)
			dummyContact := kademlia.NewContact(kademlia.NewRandomKademliaID(), targetAddr)
			if resp, err := kad.SendPing(&dummyContact); err != nil{
				fmt.Printf("Ping error: %v \n", err)
			}else {
				fmt.Printf("Ping response: %s from %s (ID: %s)\n", resp.Type, resp.Sender.Address, resp.Sender.ID)
			}

		// Retrieve the routing table 
		case "RT":
			contacts := kad.RoutingTable.GetAllContacts()
			if len(contacts) == 0 {
				fmt.Printf("Routing Table is empty.")
				continue 
			}
			fmt.Printf("Routing table for node %s (%s): \n", kad.Me.ID.String(), kad.Me.Address)
			fmt.Printf("%-4 | %-11s | %-21s \n", "No.", "Node ID", "Address")
			fmt.Printf(strings.Repeat("-", 40))

			for i, c := range contacts {
				fmt.Printf("\n %-4d | %-11s | %-21s\n", i+1, truncateID(c.ID.String()), c.Address)

			}
 
		// Lookup from nodeA to NodeB about target 
		case "LOOKUP":
			if len(fields) != 3 {
				fmt.Printf("Error Lookup requires exactly two arguments: Recipient_IP:PORT Target-ID")
				continue 
			}

			recipientAddr := fields[1]
			targetHex := fields[2]

			// validate IP:PORT format 
		  if ip, port, ok := strings.Cut(recipientAddr, ":"); !ok || port == "" || ip == "" {
				fmt.Printf("Error: Invalid Node A format, expected IP:PORT")
				continue
			}

			// Validate hex format of ID 
			if len(targetHex) != 64 {
				fmt.Printf("Error: Target ID must be 64-character hexadecimal string")
				continue
			}
			
			// search for recipient in routing table 
			var recipientContact *kademlia.Contact 
			for _, neighbor := range kad.RoutingTable.GetAllContacts() {
				if neighbor.Address == recipientAddr {
					c := neighbor
					recipientContact = &c 
					break 
				}
			}

			if recipientContact == nil {
				fmt.Printf("Error: recipient not in routing table")
				continue
			}

			targetID := kademlia.NewKademliaID(targetHex)

			fmt.Printf("Querying %s for contacts closest to %s... \n", recipientContact.Address, truncateID(targetID.String()))
			resp, err := kad.Network.SendFindContactMessage(kad.Me, recipientContact, targetID)
			if err != nil {
				fmt.Printf("Lookup error %v", err)
				continue 
			}
			contacts := resp.Contacts
			if len(contacts) == 0 {
				fmt.Printf("Recipient returned 0 contacts")
				continue
			}

			fmt.Printf("Success! Received %d closest contacts from %s \n", len(contacts), recipientContact.Address)
			for i, contact := range contacts {
				fmt.Printf("[%d] ID: %s | Address: %s \n", i + 1, truncateID(contact.ID.String()), contact.Address)
			}
		default:
			fmt.Printf("Unknown command. Type 'ping', 'lookup', or 'quit'.")



		}
	}
}

// Truncates ID to last- and first 4 characters 
func truncateID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return fmt.Sprintf("%s...%s", id[:4], id[len(id)-4:])
}
