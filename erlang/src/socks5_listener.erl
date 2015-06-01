%%%-------------------------------------------------------------------
%%% @author klimontov
%%% @copyright (C) 2014, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 19. ноя 2014 12:48
%%%-------------------------------------------------------------------
-module(socks5_listener).
-author("klimontov").

-behaviour(gen_server).

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3 ]).

-define(SERVER, ?MODULE).

-define(SOCKET_OPTIONS, [binary, {reuseaddr, true},
                                 {active, true},
                                 {nodelay, true} ]).

-define(ACCEPT_INTERVAL, 1000).
-define(ACCEPT_TIMEOUT, 100).

-record(state, {listener,
                timer_ref,
                connection_id = 0
               }).


%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
-spec(start_link() ->
    {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%% @end
%%--------------------------------------------------------------------
-spec(init(Args :: term()) ->
    {ok, State :: #state{}} | {ok, State :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term()} | ignore).
init([]) ->
    {Ip, Port} = case application:get_env(socksv5, listen) of
        undefined -> {{127,0,0,1},1080};
        {ok, IpPort} -> IpPort
    end,
    lager:info("Init listener Ip ~p Port ~p", [Ip, Port]),
    {ok, Socket} = gen_tcp:listen(Port, [{ip, Ip} | ?SOCKET_OPTIONS]),
    Timer = erlang:send_after(?ACCEPT_INTERVAL, self(), accept_connect),
    {ok, #state{listener = Socket, timer_ref = Timer}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%% @end
%%--------------------------------------------------------------------
-spec(handle_call(Request :: term(), From :: {pid(), Tag :: term()}, State :: #state{}) ->
    {reply, Reply :: term(), NewState :: #state{}} |
    {reply, Reply :: term(), NewState :: #state{}, timeout() | hibernate} |
    {noreply, NewState :: #state{}} |
    {noreply, NewState :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term(), Reply :: term(), NewState :: #state{}} |
    {stop, Reason :: term(), NewState :: #state{}}).
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%% @end
%%--------------------------------------------------------------------
-spec(handle_cast(Request :: term(), State :: #state{}) ->
    {noreply, NewState :: #state{}} |
    {noreply, NewState :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term(), NewState :: #state{}}).
handle_cast(_Request, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%% @end
%%--------------------------------------------------------------------
-spec(handle_info(Info :: timeout() | term(), State :: #state{}) ->
    {noreply, NewState :: #state{}} |
    {noreply, NewState :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term(), NewState :: #state{}}).
handle_info(accept_connect, #state{timer_ref = OldTimerRef} = State) ->
    erlang:cancel_timer(OldTimerRef),
    {_, NewState} = accept_connect_and_run_worker(State),
    TimerRef = erlang:send_after(?ACCEPT_INTERVAL, self(), accept_connect),
    {noreply, NewState#state{timer_ref = TimerRef }};



handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()), State :: #state{}) -> term()).
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
-spec(code_change(OldVsn :: term() | {down, term()}, State :: #state{}, Extra :: term()) ->
    {ok, NewState :: #state{}} | {error, Reason :: term()}).
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
accept_connect_and_run_worker(#state{ connection_id = Id, listener = Socket} = State) ->
    case gen_tcp:accept(Socket, ?ACCEPT_TIMEOUT) of
        {ok, ClientSocket} ->
            {ok, Child} = socks5_worker_sup:start_acceptor(Id, ClientSocket),
            case  gen_tcp:controlling_process(ClientSocket, Child) of
                ok ->
                     ?MODULE:accept_connect_and_run_worker(State#state{connection_id = Id+1});
                {error, Error} ->
                    lager:error("Control process didn't set. Pid: ~p Err: ~p", [Child, Error]),
                    supervisor:terminate_child(socks5_worker_sup, Child),
                    {error, State}
            end;
        {error, timeout} ->
            {ok, State};
        {error, Reason} ->
            lager:error("Accepting: ~p.", [Reason]),
            {ok, State}
    end.

