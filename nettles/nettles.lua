-- configuration file for Nettles
    
-- return table with where to connect
function on_accept_client(peer)
    print ("on_accept_client ", peer)
	return {
		connect_ip="127.0.0.1", 
		connect_port="28080",
		type = "ciphertext",
		
		trusted_ca_file = "test-ca.crt",
		certificate_file = "client1.crt",
		key_file = "client1.key",
	}
end

-- return table with where to connect
function on_accept_server(peer)
    print ("on_accept_server ", peer)
	return {
		connect_ip="google.se", 
		connect_port="80",
		type = "cleartext",
	}
end
    
-- Set up a new client, listen for incoming anything
client = add_listener{
	listen_ip="127.0.0.1", 
	listen_port="8080",
	type = "cleartext",
	
	on_accept = on_accept_client,
	}
print ("Added listener ", client)

-- Set up a new server, listen for incoming tls
server = add_listener{
	listen_ip="127.0.0.1", 
	listen_port="28080", 
	type = "ciphertext",
	
	trusted_ca_file = "test-ca.crt",
	certificate_file = "server1.crt",
	key_file = "server1.key",
	
	on_accept = on_accept_server,
	}
print ("Added listener ", server)
