%%%-------------------------------------------------------------------
%%% File    : dhcp_server.erl
%%% Author  : Ruslan Babayev <ruslan@babayev.com>
%%% Description : DHCP server
%%%
%%% Created : 20 Sep 2006 by Ruslan Babayev <ruslan@babayev.com>
%%%-------------------------------------------------------------------
-module(dhcp_udp_server).

-behaviour(gen_server).

%% API
-export([start_link/5]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include("dhcp.hrl").

-on_load(init/0).

-define(SERVER, ?MODULE).
-define(DHCP_SERVER_PORT, 67).
-define(DHCP_CLIENT_PORT, 68).
-define(INADDR_ANY, {0, 0, 0, 0}).
-define(INADDR_BROADCAST, {255, 255, 255, 255}).

-record(state, {if_name, socket, config}).

-define(is_broadcast(D), (is_record(D, dhcp) andalso (D#dhcp.flags bsr 15) == 1)).

init() ->
    LibDir = filename:join([filename:dirname(code:which(?MODULE)), "..", "priv"]),

    %% load our nif library
    case erlang:load_nif(filename:join(LibDir, "dhcp_server"), 0) of
        ok ->
            ok;
        {error, {reload, _}} ->
            ok;
        {error, Error} ->
            error_logger:error_msg("could not load dhcp_server nif library: ~p", [Error]),
            error({load_nif, Error})
    end.

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the server
%%--------------------------------------------------------------------
start_link(NetNameSpace, Interface, ServerId, NextServer, Session) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE,
			  [NetNameSpace, Interface, ServerId, NextServer, Session], []).

%%====================================================================
%% gen_server callbacks
%%====================================================================

%%--------------------------------------------------------------------
%% Function: init(Args) -> {ok, State} |
%%                         {ok, State, Timeout} |
%%                         ignore               |
%%                         {stop, Reason}
%% Description: Initiates the server
%%--------------------------------------------------------------------
init([NetNameSpace, Interface, ServerId, NextServer, Session]) ->
    Options = get_sockopt(NetNameSpace, Interface),
    io:format("Opts: ~p~n", [Options]),
    case gen_udp:open(?DHCP_SERVER_PORT, Options) of
	{ok, Socket} ->
	    lager:info("Starting DHCP server..."),
	    {ok, #state{if_name = Interface,
			socket = Socket,
			config = [#{server_id   => ServerId,
				    next_server => NextServer,
				    session     => Session}]}};
	{error, Reason} ->
	    lager:error("Cannot open udp port ~w",
				   [?DHCP_SERVER_PORT]),
	    {stop, Reason}
    end.

%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% Description: Handling call messages
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% Function: handle_cast(Msg, State) -> {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, State}
%% Description: Handling cast messages
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: handle_info(Info, State) -> {noreply, State} |
%%                                       {noreply, State, Timeout} |
%%                                       {stop, Reason, State}
%% Description: Handling all non call/cast messages
%%--------------------------------------------------------------------
handle_info({udp, Socket, IP, Port, Packet}, State = #state{socket = Socket}) ->
    Source = {IP, Port},
    Request = dhcp_lib:decode(Packet),
    case dhcp_server:optsearch(?DHO_DHCP_MESSAGE_TYPE, Request) of
	{value, MsgType} ->
	    case dhcp_server:handle_dhcp(MsgType, Request, State#state.config) of
		ok ->
		    ok;
		{reply, Reply} ->
		    send_reply(Source, MsgType, Reply, State);
		{error, Reason} ->
		    lager:error(Reason);
		Other ->
		    lager:debug("DHCP result: ~w", [Other])
	    end;
	false ->
	    ok
    end,
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: terminate(Reason, State) -> void()
%% Description: This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%%--------------------------------------------------------------------
terminate(_Reason, State) ->
    gen_udp:close(State#state.socket),
    ok.

%%--------------------------------------------------------------------
%% Func: code_change(OldVsn, State, Extra) -> {ok, NewState}
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
send_reply(Source, MsgType, Reply, State) ->
    {DstIP, DstPort} = get_dest(Source, MsgType, Reply, State),
    lager:debug("Sending DHCP Reply to: ~s:~w", [dhcp_server:fmt_ip(DstIP), DstPort]),
    gen_udp:send(State#state.socket, DstIP, DstPort, dhcp_lib:encode(Reply)).

%%% Behaviour is described in RFC2131 sec. 4.1
get_dest(Source = {SrcIP, SrcPort}, MsgType, Reply, Config)
  when is_record(Reply, dhcp) ->
    if Reply#dhcp.giaddr =/= ?INADDR_ANY ->
	    lager:debug("get_dest: #1"),
	    {Reply#dhcp.giaddr, ?DHCP_SERVER_PORT};

       Reply#dhcp.ciaddr =/= ?INADDR_ANY ->
	    lager:debug("get_dest: #2"),
	    if (MsgType =/= ?DHCPINFORM andalso SrcIP =/= Reply#dhcp.ciaddr)
	       orelse SrcIP == ?INADDR_ANY orelse SrcPort == 0 ->
		    {Reply#dhcp.ciaddr, ?DHCP_CLIENT_PORT};
	       true ->
		    Source
	    end;

       ?is_broadcast(Reply) ->
	    lager:debug("get_dest: #3"),
	    {?INADDR_BROADCAST, ?DHCP_CLIENT_PORT};

       Reply#dhcp.yiaddr =/= ?INADDR_ANY ->
	    lager:debug("get_dest: #4"),
	    arp_inject(Reply#dhcp.yiaddr, Reply#dhcp.htype, Reply#dhcp.chaddr, Config),
	    {Reply#dhcp.yiaddr, ?DHCP_CLIENT_PORT};

       true ->
	    lager:debug("get_dest: #5"),
	    Source
    end.

arp_inject_nif(_IfName, _IP, _Type, _Addr, _FD) -> error(nif_not_loaded).

arp_inject(IP, Type, Addr, #state{if_name = IfName, socket = Socket}) ->
    {ok, FD} = inet:getfd(Socket),
    lager:debug("FD: ~w", [FD]),
    arp_inject_nif(IfName, dhcp_lib:ip_to_binary(IP), Type, dhcp_lib:eth_to_binary(Addr), FD).

get_nsopts(NetNameSpace, Opts)
  when is_binary(NetNameSpace); is_list(NetNameSpace) ->
    [{netns, NetNameSpace} | Opts];
get_nsopts(_, Opts) ->
    Opts.


get_ifopts(Interface, Opts) when is_binary(Interface) ->
    %% setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, nic, IF_NAMESIZE);
    [{raw, 1, 25, Interface} | Opts].

get_fdopts(Opts) ->
    case init:get_argument(fd) of
	{ok, [[FD]]} ->
	    [{fd, list_to_integer(FD)} | Opts];
	error ->
	    Opts
    end.

get_sockopt(NetNameSpace, Interface) ->
    Opts = [binary, {broadcast, true}],
    Opts0 = get_nsopts(NetNameSpace, Opts),
    Opts1 = get_ifopts(Interface, Opts0),
    get_fdopts(Opts1).
