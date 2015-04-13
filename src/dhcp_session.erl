-module(dhcp_session).

-callback allocated(ClientId :: dhcp_server:client_id(),
		    ChAddr :: dhcp_server:chaddr_id(),
		    IP :: inet:ip4_address(),
		    Options :: [{integer(), any()}]) -> 'ok'.

-callback informed(ClientId :: dhcp_server:client_id(),
		   IP :: inet:ip4_address(),
		   Options :: [{integer(), any()}]) -> 'ok'.

-callback expired(ClientId :: dhcp_server:client_id(),
		  IP :: inet:ip4_address()) -> 'ok'.

-callback released(ClientId :: dhcp_server:client_id(),
		   IP :: inet:ip4_address()) -> 'ok'.
