-- configuration file for Nettles
-- for a server application without TLS support
-- The server application is reconfigured to listen to 127.0.0.1:443
    
-- return table with where to connect
function on_accept_server(peer)
    print ("on_accept_server ", peer)
	return {
		connect_ip="127.0.0.1", -- the server applications address
		connect_port="443", -- the server applications port
		type = "cleartext", -- don't use TLS
	}
end
    
-- Set up a new server, listen for incoming TLS
server = add_listener{
	listen_ip="0.0.0.0", -- Nettles address
	listen_port="4443", -- nettles port
	type = "ciphertext", -- use TLS
	
	trusted_ca_file = "test-ca.crt", -- the CA that we trust
	certificate_file = "server1.crt", -- the servers certificate
	key_file = "server1.key", -- the servers private key
	
	on_accept = on_accept_server, -- what to do when a client connects
	}
print ("Added listener ", server)
