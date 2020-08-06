%%%-------------------------------------------------------------------
%%% File    : dhcp_lib.erl
%%% Author  : Ruslan Babayev <ruslan@babayev.com>
%%% Description :
%%%
%%% Created : 17 Apr 2006 by Ruslan Babayev <ruslan@babayev.com>
%%%-------------------------------------------------------------------
-module(dhcp_lib).

%% API
-export([decode/1, decode/2, encode/1]).
-export([ip_to_binary/1, eth_to_binary/1]).
-export([get_opt/3, put_opt/3]).
-import(lists, [keymember/3, keysearch/3, keyreplace/4]).
-include("dhcp.hrl").

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function:
%% Description:
%%--------------------------------------------------------------------
decode(Msg) ->
    decode(Msg, list).

decode(<<Op, Htype0, Hlen, Hops,  Xid:32, Secs:16, Flags:16,
	Ciaddr:4/binary, Yiaddr:4/binary, Siaddr:4/binary, Giaddr:4/binary,
	Chaddr0:16/binary, Sname:64/binary, File:128/binary,
	Options/binary>>, Type) ->
    OptsList = case Options of
		   <<99, 130, 83, 99, Opts/binary>> ->
		       decode_options(binary_to_options(Opts));
		   _ -> %% return empty list if the MAGIC is not there
		       []
	       end,
    {Htype, Chaddr} = decode_chaddr(Htype0, Hlen, Chaddr0),
    #dhcp{op      = Op,
	  htype   = Htype,
	  hops    = Hops,
	  xid     = Xid,
	  secs    = Secs,
	  flags   = Flags,
	  ciaddr  = binary_to_ip(Ciaddr),
	  yiaddr  = binary_to_ip(Yiaddr),
	  siaddr  = binary_to_ip(Siaddr),
	  giaddr  = binary_to_ip(Giaddr),
	  chaddr  = Chaddr,
	  sname   = binary_to_list(Sname),
	  file    = binary_to_list(File),
	  options = opts_to_type(OptsList, Type)}.

encode(D) when is_record(D, dhcp) ->
    {Hlen, Chaddr} = encode_chaddr(D#dhcp.htype, D#dhcp.chaddr),

    Op      = D#dhcp.op,
    Htype   = D#dhcp.htype,
    Hops    = D#dhcp.hops,
    Xid     = D#dhcp.xid,
    Secs    = D#dhcp.secs,
    Flags   = D#dhcp.flags,
    Ciaddr  = ip_to_binary(D#dhcp.ciaddr),
    Yiaddr  = ip_to_binary(D#dhcp.yiaddr),
    Siaddr  = ip_to_binary(D#dhcp.siaddr),
    Giaddr  = ip_to_binary(D#dhcp.giaddr),
    Sname   = pad(list_to_binary(D#dhcp.sname), 64),
    File    = pad(list_to_binary(D#dhcp.file), 128),
    Opts    = options_to_binary(D#dhcp.options),
    <<Op, Htype, Hlen, Hops, Xid:32, Secs:16, Flags:16,
     Ciaddr/binary, Yiaddr/binary, Siaddr/binary, Giaddr/binary,
     Chaddr/binary, Sname/binary, File/binary, Opts/binary>>.

get_opt(Key, Opts, Default) when is_list(Opts) ->
    proplists:get_value(Key, Opts, Default);
get_opt(Key, Opts, Default) when is_map(Opts) ->
    maps:get(Key, Opts, Default).

put_opt(Key, Value, Opts) when is_list(Opts) ->
    lists:keystore(1, Key, Opts, {Key, Value});
put_opt(Key, Value, Opts) when is_map(Opts) ->
    maps:put(Key, Value, Opts).

opts_to_type(Opts, map) when is_map(Opts) -> Opts;
opts_to_type(Opts, list) when is_list(Opts) -> Opts;
opts_to_type(Opts, map) when is_list(Opts) ->
    lists:foldl(
      fun({K, V}, M) when K =:= ?DHO_VENDOR_ENCAPSULATED_OPTIONS;
			 K =:= ?DHO_DHCP_AGENT_OPTIONS ->
	      M#{K => opts_to_type(V, map)};
	 ({K, V}, M) ->
	      M#{K => V}
      end, #{}, Opts);
opts_to_type(Opts, list) when is_map(Opts) ->
    maps:fold(
      fun(K, V, L) when is_map(V) ->
	      [{K, opts_to_type(V, list)}|L];
	 (K, V, L) ->
	      [{K, V}|L]
      end, [], Opts).

%%====================================================================
%% Internal functions
%%====================================================================
binary_to_ip(<<A, B, C, D>>) ->
    {A, B, C, D}.

eth_to_binary({A, B, C, D, E, F}) ->
    <<A, B, C, D, E, F>>.

encode_chaddr(1, {A, B, C, D, E, F}) ->
    {6, pad(<<A, B, C, D, E, F>>, 16)};
encode_chaddr(_, Bin) when is_binary(Bin), size(Bin) =< 16 ->
    {size(Bin), pad(Bin, 16)}.

decode_chaddr(1, 6,  <<A, B, C, D, E, F, _/binary>>) ->
    {1, {A, B, C, D, E, F}};
decode_chaddr(Htype, Hlen, Chaddr) when Hlen =< 16 ->
    {Htype, binary:part(Chaddr, 0, Hlen)}.

ip_to_binary({A, B, C, D}) ->
    <<A, B, C, D>>.

pad(X, Size) when is_binary(X) ->
    Len  = size(X),
    Plen = Size - Len,
    <<X/binary, 0:Plen/integer-unit:8>>.

binary_to_options(Binary) ->
    binary_to_options(Binary, #{}).

binary_to_options(Tag, Bin, Opts) when is_map_key(Tag, Opts) ->
    maps:update_with(Tag, fun(V) -> <<V/binary, Bin/binary>> end, Opts);
binary_to_options(Tag, Bin, Opts) ->
    Opts#{Tag => Bin}.

binary_to_options(<<?DHO_END, _/binary>>, Opts) -> Opts;
binary_to_options(<<Tag:8, Size:8, Rest/binary>>, Opts) ->
    <<Bin:Size/bytes, Next/binary>> = Rest,
    binary_to_options(Next, binary_to_options(Tag, Bin, Opts)).

binary_to_relay_suboptions(Bin) ->
    binary_to_relay_suboptions(Bin, #{}).

binary_to_relay_suboptions(<<>>, Opts) -> Opts;
binary_to_relay_suboptions(<<Tag:8, Size:8, Rest/binary>>, Opts) ->
    <<Bin:Size/bytes, Next/binary>> = Rest,
    binary_to_relay_suboptions(Next, binary_to_options(Tag, Bin, Opts)).

decode_options(Opts) ->
    maps:map(fun(Tag, Bin) -> decode_val(Bin, type(Tag)) end, Opts).

decode_relay_options(Opts) ->
    maps:map(fun(Tag, Bin) -> decode_val(Bin, relay_type(Tag)) end, Opts).

decode_val(<<V:8>>, byte) ->
    V;
decode_val(<<V:16>>, short) ->
    V;
decode_val(Bin, shortlist) ->
    [H || <<H:16>> <= Bin];
decode_val(<<V:32>>, integer) ->
    V;
decode_val(String, string) ->
    String;
decode_val(Bin, ip) ->
    binary_to_ip(Bin);
decode_val(Bin, iplist) ->
    [binary_to_ip(IP) || <<IP:4/bytes>> <= Bin];
decode_val(<<1:8, Bin/binary>>, sip_servers) ->
    [binary_to_ip(IP) || <<IP:4/bytes>> <= Bin];
decode_val(Vendor, vendor) ->
    binary_to_options(Vendor);
decode_val(Bin, relay_options) ->
    decode_relay_options(binary_to_relay_suboptions(Bin));
decode_val(Bin, unknown) ->
    Bin.

options_to_binary(Options) when is_list(Options) ->
    B = << <<(option_to_binary(Tag, Val))/binary>> || {Tag, Val} <- Options >>,
    <<?DHCP_OPTIONS_COOKIE/binary, B/binary, ?DHO_END>>;
options_to_binary(Options) when is_map(Options) ->
    B = maps:fold(fun(Tag, Val, Acc) ->
			  <<Acc/binary, (option_to_binary(Tag, Val))/binary>>
		  end, ?DHCP_OPTIONS_COOKIE, Options),
    <<B/binary, ?DHO_END>>.

option_to_binary(Tag, Val) ->
    encode_opt(Tag, encode_val(type(Tag), Val)).

encode_relay(Tag, Val) ->
    Bin = encode_val(relay_type(Tag), Val),
    <<Tag:8, (size(Bin)):8, Bin/binary>>.

encode_opt(Tag, <<Bin:255/bytes, Rest/binary>>) ->
    << (encode_opt(Tag, Bin))/binary, (encode_opt(Tag, Rest))/binary >>;
encode_opt(Tag, Bin) ->
    <<Tag:8, (size(Bin)):8, Bin/binary>>.

encode_val(byte, Val) ->
    <<Val:8>>;
encode_val(short, Val) ->
    <<Val:16>>;
encode_val(shortlist, Val) ->
    << <<S:16>> || S <- Val >>;
encode_val(integer, Val) ->
    <<Val:32>>;
encode_val(string, Val) when is_binary(Val) ->
    Val;
encode_val(string, Val) when is_list(Val) ->
    list_to_binary(Val);
encode_val(ip, Val) ->
    ip_to_binary(Val);
encode_val(iplist, Val) ->
    << <<(ip_to_binary(IP))/binary>> || IP <- Val >>;
encode_val(sip_servers, [{_,_,_,_}|_] = Val) ->
    <<1:8, << <<(ip_to_binary(IP))/binary>> || IP <- Val >>/binary>>;
encode_val(vendor, Val) when is_binary(Val) ->
    << <<Tag:8, (size(Bin)):8, Bin/binary>> || {Tag, Bin} <- Val >>;
encode_val(relay_options, Val) when is_map(Val) ->
    << <<(encode_relay(T,V))/binary>> || {T, V} <- maps:to_list(Val) >>;
encode_val(relay_options, Val) when is_list(Val) ->
    << <<(encode_relay(T,V))/binary>> || {T, V} <- Val >>.

%%% DHCP Option types
type(?DHO_SUBNET_MASK)                 -> ip;
type(?DHO_TIME_OFFSET)                 -> integer;
type(?DHO_ROUTERS)                     -> iplist;
type(?DHO_TIME_SERVERS)                -> iplist;
type(?DHO_NAME_SERVERS)                -> iplist;
type(?DHO_DOMAIN_NAME_SERVERS)         -> iplist;
type(?DHO_LOG_SERVERS)                 -> iplist;
type(?DHO_COOKIE_SERVERS)              -> iplist;
type(?DHO_LPR_SERVERS)                 -> iplist;
type(?DHO_IMPRESS_SERVERS)             -> iplist;
type(?DHO_RESOURCE_LOCATION_SERVERS)   -> iplist;
type(?DHO_HOST_NAME)                   -> string;
type(?DHO_BOOT_SIZE)                   -> short;
type(?DHO_MERIT_DUMP)                  -> string;
type(?DHO_DOMAIN_NAME)                 -> string;
type(?DHO_SWAP_SERVER)                 -> ip;
type(?DHO_ROOT_PATH)                   -> string;
type(?DHO_EXTENSIONS_PATH)             -> string;
type(?DHO_IP_FORWARDING)               -> byte;
type(?DHO_NON_LOCAL_SOURCE_ROUTING)    -> byte;
type(?DHO_POLICY_FILTER)               -> iplist;
type(?DHO_MAX_DGRAM_REASSEMBLY)        -> short;
type(?DHO_DEFAULT_IP_TTL)              -> byte;
type(?DHO_PATH_MTU_AGING_TIMEOUT)      -> integer;
type(?DHO_PATH_MTU_PLATEAU_TABLE)      -> integer;
type(?DHO_INTERFACE_MTU)               -> short;
type(?DHO_ALL_SUBNETS_LOCAL)           -> byte;
type(?DHO_BROADCAST_ADDRESS)           -> ip;
type(?DHO_PERFORM_MASK_DISCOVERY)      -> byte;
type(?DHO_MASK_SUPPLIER)               -> byte;
type(?DHO_ROUTER_DISCOVERY)            -> byte;
type(?DHO_ROUTER_SOLICITATION_ADDRESS) -> ip;
type(?DHO_STATIC_ROUTES)               -> iplist;
type(?DHO_TRAILER_ENCAPSULATION)       -> byte;
type(?DHO_ARP_CACHE_TIMEOUT)           -> integer;
type(?DHO_IEEE802_3_ENCAPSULATION)     -> byte;
type(?DHO_DEFAULT_TCP_TTL)             -> byte;
type(?DHO_TCP_KEEPALIVE_INTERVAL)      -> integer;
type(?DHO_TCP_KEEPALIVE_GARBAGE)       -> byte;
type(?DHO_NIS_DOMAIN)                  -> string;
type(?DHO_NIS_SERVERS)                 -> iplist;
type(?DHO_NTP_SERVERS)                 -> iplist;
type(?DHO_TFTP_SERVER_NAME)            -> string;
type(?DHO_BOOTFILE_NAME)               -> string;
type(?DHO_VENDOR_ENCAPSULATED_OPTIONS) -> vendor;
type(?DHO_NETBIOS_NAME_SERVERS)        -> iplist;
type(?DHO_NETBIOS_DD_SERVERS)          -> iplist;
type(?DHO_NETBIOS_NODE_TYPE)           -> byte;
type(?DHO_NETBIOS_SCOPE)               -> string;
type(?DHO_FONT_SERVERS)                -> iplist;
type(?DHO_X_DISPLAY_MANAGERS)          -> iplist;
type(?DHO_DHCP_REQUESTED_ADDRESS)      -> ip;
type(?DHO_DHCP_LEASE_TIME)             -> integer;
type(?DHO_DHCP_OPTION_OVERLOAD)        -> byte;
type(?DHO_DHCP_MESSAGE_TYPE)           -> byte;
type(?DHO_DHCP_SERVER_IDENTIFIER)      -> ip;
type(?DHO_DHCP_PARAMETER_REQUEST_LIST) -> string;
type(?DHO_DHCP_MESSAGE)                -> string;
type(?DHO_DHCP_MAX_MESSAGE_SIZE)       -> short;
type(?DHO_DHCP_RENEWAL_TIME)           -> integer;
type(?DHO_DHCP_REBINDING_TIME)         -> integer;
type(?DHO_VENDOR_CLASS_IDENTIFIER)     -> string;
type(?DHO_DHCP_CLIENT_IDENTIFIER)      -> string;
type(?DHO_NWIP_DOMAIN_NAME)            -> string;
type(?DHO_NIS_PLUS_DOMAIN)             -> string;
type(?DHO_NIS_PLUS_SERVERS)            -> iplist;
type(?DHO_MOBILE_IP_HOME_AGENTS)       -> iplist;
type(?DHO_SMTP_SERVERS)                -> iplist;
type(?DHO_POP3_SERVERS)                -> iplist;
type(?DHO_WWW_SERVERS)                 -> iplist;
type(?DHO_FINGER_SERVERS)              -> iplist;
type(?DHO_IRC_SERVERS)                 -> iplist;
type(?DHO_STREETTALK_SERVERS)          -> iplist;
type(?DHO_STDA_SERVERS)                -> iplist;
type(?DHO_USER_CLASS)                  -> string;
type(?DHO_FQDN)                        -> string;
type(?DHO_DHCP_AGENT_OPTIONS)          -> relay_options;
type(?DHO_NDS_SERVERS)                 -> iplist;
type(?DHO_NDS_TREE_NAME)               -> string;
type(?DHO_NDS_CONTEXT)                 -> string;
type(?DHO_UAP)                         -> string;
type(?DHO_AUTO_CONFIGURE)              -> byte;
type(?DHO_NAME_SERVICE_SEARCH)         -> shortlist;
type(?DHO_SUBNET_SELECTION)            -> ip;
type(?DHO_SIP_SERVERS)                 -> sip_servers;
type(?DHO_TFTP_SERVER_ADDRESS)         -> ip;
type(_)                                -> unknown.

relay_type(?RAI_CIRCUIT_ID)                  -> string;
relay_type(?RAI_REMOTE_ID)                   -> string;
relay_type(?RAI_AGENT_ID)                    -> string;
relay_type(?RAI_DOCSIS_DEVICE_CLASS)         -> string;
relay_type(?RAI_LINK_SELECTION)              -> ip;
relay_type(?RAI_SUBSCRIBER_ID)               -> string;
relay_type(?RAI_RADIUS_ATTRIBUTES)           -> string;
relay_type(?RAI_AUTHENTICATION)              -> string;
relay_type(?RAI_VENDOR_SPECIFIC_INFORMATION) -> string;
relay_type(?RAI_RELAY_AGENT_FLAGS)           -> byte;
relay_type(?RAI_SERVER_IDENTIFIER_OVERRIDE)  -> ip;
relay_type(?RAI_RELAY_AGENT_IDENTIFIER)      -> string;
relay_type(?RAI_ACCESS_TECHNOLOGY_TYPE)      -> byte;
relay_type(?RAI_ACCESS_NETWORK_NAME)         -> string;
relay_type(?RAI_ACCESS_POINT_NAME)           -> string;
relay_type(?RAI_ACCESS_POINT_BSSID)          -> string;
relay_type(?RAI_OPERATOR_IDENTIFIER)         -> integer;
relay_type(?RAI_OPERATOR_REALM)              -> string;
relay_type(?RAI_DHCPV4_RELAY_SOURCE_PORT)    -> short;
relay_type(_)                                -> unknown.
