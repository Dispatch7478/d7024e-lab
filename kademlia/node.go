package kademlia 

import (
	"fmt"
	"net"
	"log"
)

// Node represents the nodes within the network
type Node struct {
	Kademlia *Kademlia
	Network *Network
}

// NewNode boots the kademlia instance, initializes routing, and binds the UDP listener
func NewNode(port int, bootstrapIP string) (*Kademlia, error){
	//get ip of conatiner
	localIP, err := getLocalIP()
	if err != nil {
		return nil, fmt.Errorf("Failed to discover container ip: %v", err)
	}

	// create node identity
	localAddr := fmt.Sprint("%s:%d", localIP, port)
	me := NewContact(NewRandomKademliaID(), localAddr)
	kad := NewKademlia(me)

	// bind UDP listener 
	if err := kad.Network.Listen(localIP, port); err != nil {
		return nil, fmt.Errorf("Failed to listen on port %d: %v", port, err)
	}

	log.Printf("Initialization step sucessfull: Kademlia node initialized at %s with ID %s", me.Address, me.ID.String())

	if bootstrapIP != "" && bootstrapIP != localIP {
		bootstrapAddr := fmt.Sprintf("%s:%d", bootstrapIP, port)
		log.Printf("Connecting to bootstrap node at %s", bootstrapAddr)

		// temp contact to ping bootstrap node
		bootstrapContact := NewContact(NewRandomKademliaID(), bootstrapAddr)
		resp, err := kad.SendPing(&bootstrapContact)
		if err != nil{
			log.Printf("bootstrap ping failed: %v", err)

		}else{
			// update contact with the real ID returned in response 
			realBootstrapContact := resp.Sender 
			kad.RoutingTable.AddContact(realBootstrapContact)
			log.Printf("Successfully pinged bootstrap node %s (ID: %s)", realBootstrapContact.Address, realBootstrapContact.ID)
		}
	}
	return kad, nil 
}


// Discovers the ip address of the docker container assigned to this node.

func getLocalIP() (string, error) {

	// get all addresses of all interfaces 
	addrs, err := net.InterfaceAddrs()

	if err != nil{
		return "", err 
	}

	// loop through, excluding loopback interfaces and ipv6 addresses
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
	
			}
		}
	}
	
	return "", fmt.Errorf("no valid non-loopback IPv4 address found") 

}
