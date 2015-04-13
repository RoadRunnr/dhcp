%%%-------------------------------------------------------------------
%%% File    : dhcp_server.erl
%%% Author  : Ruslan Babayev <ruslan@babayev.com>
%%% Description : DHCP server
%%%
%%% Created : 20 Sep 2006 by Ruslan Babayev <ruslan@babayev.com>
%%%-------------------------------------------------------------------
-module(dhcp_raw_server).

-behaviour(gen_server).

%% API
-export([start_link/3, handle_dhcp/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include("dhcp.hrl").

-define(SERVER, ?MODULE).
-define(DHCP_RAW_PORT, 6767).
-define(DHCP_SERVER_PORT, 67).
-define(DHCP_CLIENT_PORT, 68).
-define(INADDR_ANY, {0, 0, 0, 0}).
-define(INADDR_BROADCAST, {255, 255, 255, 255}).

%% -define(SESSION, dhcp_session).
-define(SESSION, scg_b_session).

-record(state, {config}).

-define(is_broadcast(D), (is_record(D, dhcp) andalso (D#dhcp.flags bsr 15) == 1)).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the server
%%--------------------------------------------------------------------
start_link(ServerId, NextServer, Session) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE,
			  [ServerId, NextServer, Session], []).

handle_dhcp(Packet) when is_binary(Packet) ->
    gen_server:call(?SERVER, {dhcp, Packet}).

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
init([ServerId, NextServer, Session]) ->
    lager:info("Starting DHCP server..."),
    {ok, #state{config = [#{server_id   => ServerId,
			    next_server => NextServer,
			    session     => Session}]}}.

%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% Description: Handling call messages
%%--------------------------------------------------------------------
handle_call({dhcp, <<_IhlVer:8/integer, _Tos:8/integer, _TotLen:16/integer,
		     _Id:16/integer, _FragOff:16/integer, _Ttl:8/integer, _Proto:8/integer,
		     _IPCsum:16/integer, SrcIP:4/bytes, _DstIP:4/bytes,
		     SrcPort:16/integer, _DstPort:16/integer, _UDPLen:16/integer, _UDPCsum:16/integer,
		     Packet/binary>>}, From, State) ->
    Source = {SrcIP, SrcPort},
    Request = dhcp_lib:decode(Packet),
    lager:debug("DHCP Request: ~p, ~p", [Source, Request]),
    case dhcp_server:optsearch(?DHO_DHCP_MESSAGE_TYPE, Request) of
	{value, MsgType} ->
	    case dhcp_server:handle_dhcp(MsgType, Request, State#state.config) of
		ok ->
		    ok;
		{reply, Reply} ->
		    send_reply(From, Source, MsgType, Reply);
		{error, Reason} ->
		    lager:error(Reason);
		Other ->
		    lager:debug("DHCP result: ~w", [Other])
	    end;
	false ->
	    ok
    end,
    {noreply, State};
handle_call(_Request, _From, State) ->
    lager:error("unknown call: ~p", [_Request]),
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
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: terminate(Reason, State) -> void()
%% Description: This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
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
send_reply(From, Source, MsgType, Reply) ->
    {DstIP, DstPort} = get_dest(Source, MsgType, Reply),
    lager:debug("Sending DHCP Reply to: ~w:~w", [DstIP, DstPort]),
    gen_server:reply(From, {reply, DstIP, DstPort, dhcp_lib:encode(Reply)}).

%%% Behaviour is described in RFC2131 sec. 4.1
get_dest(Source = {SrcIP, SrcPort}, MsgType, Reply)
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
	    {{{Reply#dhcp.htype, Reply#dhcp.chaddr}, Reply#dhcp.yiaddr}, ?DHCP_CLIENT_PORT};

       true ->
	    lager:debug("get_dest: #5"),
	    Source
    end.
