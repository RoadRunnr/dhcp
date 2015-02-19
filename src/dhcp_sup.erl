%%%-------------------------------------------------------------------
%%% File    : dhcp_sup.erl
%%% Author  : Ruslan Babayev <ruslan@babayev.com>
%%% Description :
%%%
%%% Created : 20 Sep 2006 by Ruslan Babayev <ruslan@babayev.com>
%%%-------------------------------------------------------------------
-module(dhcp_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).
-export([get_config/0]).
%% Supervisor callbacks
-export([init/1]).

-import(lists, [keysearch/3, filter/2]).

-include("dhcp_alloc.hrl").

-define(SERVER, ?MODULE).
-define(DHCP_LEASEFILE, "/var/run/dhcp_leases.dets").

%%====================================================================
%% API functions
%%====================================================================
%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the supervisor
%%--------------------------------------------------------------------
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================
%%--------------------------------------------------------------------
%% Func: init(Args) -> {ok,  {SupFlags,  [ChildSpec]}} |
%%                     ignore                          |
%%                     {error, Reason}
%% Description: Whenever a supervisor is started using
%% supervisor:start_link/[2,3], this function is called by the new process
%% to find out about restart strategy, maximum restart frequency and child
%% specifications.
%%--------------------------------------------------------------------
init([]) ->
    case get_config() of
        {ok, NetNameSpace, Interface, ServerId, NextServer, LeaseFile, Subnets, Hosts} ->
            DHCPServer = {dhcp_server, {dhcp_server, start_link,
                                        [NetNameSpace, Interface, ServerId, NextServer]},
                          permanent, 2000, worker, [dhcp_server]},
            DHCPAlloc = {dhcp_alloc, {dhcp_alloc, start_link,
                                      [LeaseFile, Subnets, Hosts]},
                         permanent, 2000, worker, [dhcp_alloc]},
            {ok, {{one_for_one, 0, 1}, [DHCPServer, DHCPAlloc]}};
        {error, Reason} ->
            {error, Reason}
    end.

%%====================================================================
%% Internal functions
%%====================================================================

get_config() ->
    Config = application:get_all_env(),
    io:format("Config: ~p~n", [Config]),
    case process_config(Config) of
	{error, _} ->
	    get_config_file();
	Other ->
	    Other
    end.

get_config_file() ->
    ConfDir = case code:priv_dir(dhcp) of
		  PrivDir when is_list(PrivDir) -> PrivDir;
                  {error, _Reason} -> "."
              end,
    case file:consult(filename:join(ConfDir, "dhcp.conf")) of
        {ok, Terms} ->
	    process_config(Terms);
        {error, Reason} ->
	    {error, Reason}
    end.

process_config(Config) ->
    case lists:keyfind(subnets, 1, Config) of
	false ->
	    {error, no_subnet_declaration};
	_ ->
	    NetNameSpace = proplists:get_value(netns,       Config),
	    Interface =    proplists:get_value(interface,   Config),
	    ServerId =     proplists:get_value(server_id,   Config, {0, 0, 0, 0}),
	    NextServer =   proplists:get_value(next_server, Config, {0, 0, 0, 0}),
	    LeaseFile =    proplists:get_value(lease_file,  Config, ?DHCP_LEASEFILE),
	    Subnets =      [X || X <- proplists:get_value(subnets, Config, []), is_record(X, subnet)],
	    Hosts =        [X || X <- proplists:get_value(hosts,   Config, []), is_record(X, host)],
	    {ok, NetNameSpace, Interface, ServerId, NextServer, LeaseFile, Subnets, Hosts}
    end.
