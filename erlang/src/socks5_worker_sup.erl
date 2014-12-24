%%%-------------------------------------------------------------------
%%% @author klimontov
%%% @copyright (C) 2014, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 19. ноя 2014 12:42
%%%-------------------------------------------------------------------
-module(socks5_worker_sup).
-author("klimontov").

-behaviour(supervisor).

%% API
-export([start_link/0,
         start_acceptor/2]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%% @end
%%--------------------------------------------------------------------
-spec(start_link() ->
    {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_acceptor(Id, Socket) ->
    lager:info("Start chield worker sup"),
    Restart  = temporary,
    Shutdown = 3000,
    Type     = worker,
    AChild   = {{socks5_worker, Id ,Socket}, {socks5_worker, start_link, [Socket]},
               Restart, Shutdown, Type, [socks5_worker]},
    supervisor:start_child(?SERVER, AChild).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart frequency and child
%% specifications.
%% @end
%%--------------------------------------------------------------------
-spec(init(Args :: term()) ->
    {ok, {SupFlags :: {RestartStrategy :: supervisor:strategy(), MaxR :: non_neg_integer(), MaxT :: non_neg_integer()},
     [ChildSpec :: supervisor:child_spec()] }}
    | ignore | {error, Reason :: term()}).
init([]) ->
    lager:info("Init worker sup"),
    RestartStrategy = one_for_one,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,
    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},
    {ok, {SupFlags, []}}.
