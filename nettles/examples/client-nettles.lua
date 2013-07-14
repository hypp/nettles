-- configuration file for Nettles
-- for a client application without TLS support
-- The client application is reconfigured to connect to 127.0.0.1:8080
-- The servers address and port is entered below (connect_ip and connect_port)
    
-- return table with where to connect
function on_accept_client(peer)
    print ("on_accept_client ", peer)
	return {
		connect_ip="myserver", -- the servers address
		connect_port="443", -- the servers port
		type = "ciphertext", -- use TLS
		
		trusted_ca_file = "test-ca.crt", -- the CA that we trust
		certificate_file = "client1.crt", -- the clients certificate
		key_file = "client1.key", -- the clients private key
	}
end
    
-- Set up a new client, listen for incoming anything
client = add_listener{
	listen_ip="127.0.0.1", -- Nettles address
	listen_port="8080", -- nettles port
	type = "cleartext", -- don't use TLS
	
	on_accept = on_accept_client, -- what to do when a client connects
	}
print ("Added listener ", client)
