%%%-------------------------------------------------------------------
%%% File    : dhcp_server.erl
%%% Author  : Ruslan Babayev <ruslan@babayev.com>
%%% Description : DHCP server
%%%
%%% Created : 20 Sep 2006 by Ruslan Babayev <ruslan@babayev.com>
%%%-------------------------------------------------------------------
-module(dhcp_server).

%% API
-export([fmt_clientid/1, fmt_ip/1]).
-export([handle_dhcp/3, expired/3]).

-include_lib("kernel/include/logger.hrl").
-include("dhcp.hrl").

-define(INADDR_ANY, {0, 0, 0, 0}).

-define(is_broadcast(D), (is_record(D, dhcp) andalso (D#dhcp.flags bsr 15) == 1)).

%%%-------------------------------------------------------------------
%%% The DHCP message handler
%%%-------------------------------------------------------------------
handle_dhcp(?DHCPDISCOVER, D, Config) ->
    ?LOG(info, "DHCPDISCOVER from ~s ~s ~s",
			  [fmt_clientid(D), fmt_hostname(D), fmt_gateway(D)]),
    ClientId = get_client_id(D),
    Gateway = D#dhcp.giaddr,
    RequestedIP = get_requested_ip(D),
    case dhcp_alloc:reserve(ClientId, Gateway, RequestedIP) of
	{ok, IP, Options} ->
	    offer(D, IP, Options, Config);
	Other ->
	    Other
    end;
handle_dhcp(?DHCPREQUEST, D, Config) ->
    ClientId = get_client_id(D),
    ?LOG(info, "DHCPREQUEST from ~s ~s ~s",
			  [fmt_clientid(D), fmt_hostname(D), fmt_gateway(D)]),
    case client_state(D) of
	{selecting, ServerId} ->
	    case {ServerId, cfg(server_id, Config, ?INADDR_ANY)} of
		{X, X} ->
		    IP = get_requested_ip(D),
		    case dhcp_alloc:allocate(ClientId, IP) of
			{ok, IP, Options} ->
			    allocated(ClientId, D#dhcp.chaddr, IP, D#dhcp.options, cfg(session, Config)),
			    ack(D, IP, Options, Config);
			Other ->
			    Other
		    end;
		_ ->
		    %% Client selected someone else, do nothing
		    ok
	    end;
	{init_reboot, RequestedIP} ->
	    Gateway = D#dhcp.giaddr,
	    case dhcp_alloc:verify(ClientId, Gateway, RequestedIP) of
		{ok, IP, Options} ->
		    allocated(ClientId, D#dhcp.chaddr, IP, D#dhcp.options, cfg(session, Config)),
		    ack(D, IP, Options, Config);
		nolease ->
		    ?LOG(error, "Client ~s has no current bindings",
					   [fmt_clientid(D)]),
		    ok;
		{error, Reason} ->
		    nak(D, Reason, Config)
	    end;
	{ClientIs, IP} when ClientIs == renewing; ClientIs == rebinding ->
	    case dhcp_alloc:extend(ClientId, IP) of
		{ok, IP, Options} ->
		    allocated(ClientId, D#dhcp.chaddr, IP, D#dhcp.options, cfg(session, Config)),
		    ack(D, IP, Options, Config);
		{error, Reason} ->
		    nak(D, Reason, Config)
	    end
    end;
handle_dhcp(?DHCPDECLINE, D, _Config) ->
    ClientId = get_client_id(D),
    IP = get_requested_ip(D),
    ?LOG(info, "DHCPDECLINE of ~s from ~s ~s",
			  [fmt_ip(IP), fmt_clientid(D), fmt_hostname(D)]),
    dhcp_alloc:decline(ClientId, IP);
handle_dhcp(?DHCPRELEASE, D, Config) ->
    ClientId = get_client_id(D),
    ?LOG(info, "DHCPRELEASE of ~s from ~s ~s ~s",
			  [fmt_ip(D#dhcp.ciaddr), fmt_clientid(D),
			   fmt_hostname(D), fmt_gateway(D)]),
    dhcp_alloc:release(ClientId, D#dhcp.ciaddr),
    released(ClientId, D#dhcp.ciaddr, cfg(session, Config));
handle_dhcp(?DHCPINFORM, D, Config) ->
    ClientId = get_client_id(D),
    Gateway = D#dhcp.giaddr,
    IP = D#dhcp.ciaddr,
    ?LOG(info, "DHCPINFORM of ~s from ~s", [fmt_ip(IP), fmt_clientid(D)]),
    case dhcp_alloc:local_conf(Gateway) of
	{ok, Opts} ->
	    %% No Lease Time (RFC2131 sec. 4.3.5)
	    OptsSansLease = lists:keydelete(?DHO_DHCP_LEASE_TIME, 1, Opts),
	    informed(ClientId, IP, D#dhcp.options, cfg(session, Config)),
	    ack(D, IP, OptsSansLease, Config);
	Other ->
	    Other
    end;
handle_dhcp(MsgType, _D, _Config) ->
    ?LOG(error, "Invalid DHCP message type ~p", [MsgType]),
    ok.

client_state(#dhcp{options = #{?DHO_DHCP_SERVER_IDENTIFIER := ServerId}}) ->
    {selecting, ServerId};
client_state(#dhcp{options = #{?DHO_DHCP_REQUESTED_ADDRESS := RequestedIP}}) ->
    {init_reboot, RequestedIP};
client_state(D) when ?is_broadcast(D) ->
    {renewing, D#dhcp.ciaddr};
client_state(D) ->
    {rebinding, D#dhcp.ciaddr}.

-define(reply(DHCP), {reply, DHCP}).
reply(MsgType, D, Opts0, Config) ->
    Opts =
	case maps:get(?DHO_DHCP_AGENT_OPTIONS, D#dhcp.options, undefined) of
	    undefined -> Opts0;
	    AgentOpts -> [{?DHO_DHCP_AGENT_OPTIONS, AgentOpts} | Opts0]
	end,

    {reply, D#dhcp{
	      op = ?BOOTREPLY,
	      hops = 0,
	      secs = 0,
	      options = [{?DHO_DHCP_MESSAGE_TYPE, MsgType},
			 {?DHO_DHCP_SERVER_IDENTIFIER, cfg(server_id, Config, ?INADDR_ANY)} |
			 Opts]}}.

offer(D, IP, Options, Config) ->
    ?LOG(info, "DHCPOFFER on ~s to ~s ~s ~s",
	       [fmt_ip(IP), fmt_clientid(D),
		fmt_hostname(D), fmt_gateway(D)]),
    reply(?DHCPOFFER, D#dhcp{ciaddr = ?INADDR_ANY,
			     yiaddr = IP,
			     siaddr = cfg(next_server, Config, ?INADDR_ANY)
			    },
	  Options, Config).

ack(D, IP, Options, Config) ->
    ?LOG(info, "DHCPACK on ~s to ~s ~s ~s",
			  [fmt_ip(IP), fmt_clientid(D),
			   fmt_hostname(D), fmt_gateway(D)]),

    reply(?DHCPACK, D#dhcp{yiaddr = IP,
			   siaddr = cfg(next_server, Config, ?INADDR_ANY)
			  },
	  Options, Config).

nak(D, Reason, Config) ->
    ?LOG(info, "DHCPNAK to ~s ~s ~s. ~s",
			  [fmt_clientid(D), fmt_hostname(D),
			   fmt_gateway(D), Reason]),
    reply(?DHCPNAK, D#dhcp{ciaddr = ?INADDR_ANY,
			   yiaddr = ?INADDR_ANY,
			   siaddr = ?INADDR_ANY,
			   flags = D#dhcp.flags bor 16#8000  %% set broadcast bit
			  },
	  [{?DHO_DHCP_MESSAGE, Reason}], Config).

get_client_id(#dhcp{chaddr = ChAddr, options = Opts}) ->
    maps:get(?DHO_DHCP_CLIENT_IDENTIFIER, Opts, ChAddr).

get_requested_ip(#dhcp{options = Opts}) ->
    maps:get(?DHO_DHCP_REQUESTED_ADDRESS, Opts, ?INADDR_ANY).

to_hex([], Acc) ->
    lists:flatten(lists:reverse(Acc));
to_hex([X|Tail], Acc) ->
    to_hex(Tail, [io_lib:format("~2.16.0b", [X])|Acc]).

fmt_clientid(D) when is_record(D, dhcp) ->
    fmt_clientid(get_client_id(D));
fmt_clientid([1, E1, E2, E3, E4, E5, E6]) ->
    fmt_clientid({E1, E2, E3, E4, E5, E6});
fmt_clientid(Id) when is_list(Id) ->
    to_hex(Id, []);
fmt_clientid(Id) when is_binary(Id) ->
    lists:flatten(
      lists:join($:, [io_lib:format("~2.16.0b", [X]) || <<X:8>> <= Id]));
fmt_clientid({E1, E2, E3, E4, E5, E6}) ->
    lists:flatten(
      io_lib:format("~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b",
	     [E1, E2, E3, E4, E5, E6])).

fmt_gateway(#dhcp{giaddr = ?INADDR_ANY}) ->
    [];
fmt_gateway(#dhcp{giaddr = IP}) ->
    lists:flatten(io_lib:format("via ~s", [fmt_ip(IP)])).

fmt_hostname(#dhcp{options = #{?DHO_HOST_NAME := Hostname}}) ->
    lists:flatten(io_lib:format("(~s)", [Hostname]));
fmt_hostname(_) ->
    [].

fmt_ip({A1, A2, A3, A4}) ->
    io_lib:format("~w.~w.~w.~w", [A1, A2, A3, A4]).

cfg(Opt, Config) ->
    cfg(Opt, Config, undefined).

cfg(Opt, Config, Default)
  when is_list(Config) ->
    proplists:get_value(Opt, Config, Default);
cfg(Opt, Config, Default)
  when is_map(Config) ->
    maps:get(Opt, Config, Default).


allocated(ClientId, ChAddr, IP, Options, Session) ->
    invoke_session(allocated, [ClientId, ChAddr, IP, Options], Session).

informed(ClientId, IP, Options, Session) ->
    invoke_session(informed, [ClientId, IP, Options], Session).

expired(ClientId, IP, Session) ->
    invoke_session(expired, [ClientId, IP], Session).

released(ClientId, IP, Session) ->
    invoke_session(released, [ClientId, IP], Session).

invoke_session(_Event, _Args, undefined) ->
    ?LOG(error, "Event for undefined session: ~p(~p)", [_Event, _Args]),
    ok;
invoke_session(Event, Args, Session) ->
    try
	erlang:apply(Session, Event, Args)
    catch
	Class:Error ->
	    ?LOG(error, "DHCP Session callback ~s:~s(~w) failed with ~w:~w", [Session, Event, Args, Class, Error]),
	    ok
    end.
