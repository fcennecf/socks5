%%%-------------------------------------------------------------------
%%% @author klimontov
%%% @copyright (C) 2014, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 19. ноя 2014 12:43
%%%-------------------------------------------------------------------
-module(socks5_worker).
-author("klimontov").

-behaviour(gen_fsm).

%% API
-export([start_link/1]).

%% gen_fsm callbacks
-export([init/1,
         handle_event/3,
         handle_sync_event/4,
         handle_info/3,
         terminate/3,
         code_change/4]).

% State
-export([authentication/2,
         authentication/3,
         handshake/2,
         connect/2,
         bind/2,
         udp_associate/2,
         transfer_data/2,
         fin/2 ]).

-define(SERVER, ?MODULE).


-define(SOCKET_OPTIONS, [binary, {reuseaddr, true},
    {active, true},
    {nodelay, true} ]).


-record(state, {is_conect_set = false,
                cln_socket,
                trg_socket
                %cln_bind_socket,
                %udp_socket
               }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%% @end
%%--------------------------------------------------------------------
-spec(start_link(Args:: port()) -> {ok, pid()} | ignore | {error, Reason :: term()}).
start_link(ClientSocket) ->
    gen_fsm:start_link(?MODULE, ClientSocket, []).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm is started using gen_fsm:start/[3,4] or
%% gen_fsm:start_link/[3,4], this function is called by the new
%% process to initialize.
%% @end
%%--------------------------------------------------------------------
-spec(init(Args :: term()) ->
    {ok, StateName :: atom(), StateData :: #state{}} |
    {ok, StateName :: atom(), StateData :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term()} | ignore).
init(ClientSocket) ->
    lager:info("Init worker ~p.", [ClientSocket]),
    {ok, authentication, #state{cln_socket = ClientSocket}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_event/2, the instance of this function with the same
%% name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%% @end
%%--------------------------------------------------------------------
-spec(authentication(Event:: term(), State :: #state{}) ->
    {next_state, NextStateName :: atom(), NextState :: #state{}} |
    {next_state, NextStateName :: atom(), NextState :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term(), NewState :: #state{}}).
authentication({ok, BinData}, #state{cln_socket=Socket} = State ) ->
    case socks5_protocol:decode(authentication, BinData) of
        {ok, {_, LAuthTypes}} ->
            IsAuth = lists:member(0, LAuthTypes),
            Answer= socks5_protocol:encode(authentication, {IsAuth, 0}),
            %lager:info("Socket ~p. Authentication ~p", [Socket, Answer]),
            send_data(Socket, Answer, State),
            {next_state, handshake, State};
        {error, Reason}->
            lager:error("Socket ~p. Authentication decode error ~p", [Socket, Reason]),
            ?MODULE:fin(close, State)
    end;

authentication(_Event, State ) ->
    ?MODULE:fin(close, State).

handshake({ok, BinData}, #state{cln_socket=Socket} = State ) ->
    case socks5_protocol:decode(handshake, BinData) of
        {ok, {CMD, AddrPort}} ->
            ?MODULE:CMD(AddrPort, State);
        {error, Reason}->
            lager:error("Socket ~p. Authentication decode error ~p.", [Socket, Reason]),
            ?MODULE:fin(close, State)
    end;

handshake(_Event, State ) ->
    ?MODULE:fin(close, State).

connect({IpType, {Address, <<PortInt:16>> = Port}},  #state{cln_socket=ClientSocket} = State ) ->
    AddressTuple = socks5_protocol:convert_addres_to_inet_format(IpType, Address),
    lager:info("CONNECT ClientSocket ~p to [ IP ~p Address ~p]", [ClientSocket, AddressTuple, PortInt]),
    case gen_tcp:connect(AddressTuple, PortInt, ?SOCKET_OPTIONS) of
        {ok, TargetSocket} ->
            Data = socks5_protocol:encode(connect,{IpType, Address, Port}, 0 ),
            send_data(ClientSocket, Data, State),
            {next_state, handshake, State#state{is_conect_set = true, trg_socket = TargetSocket }};
        {error, Reason} ->
            lager:error("Socket to target host connected. Reason : ~p",[Reason]),
            Data = socks5_protocol:encode(connect,{IpType, Address, Port}, 4 ),
            send_data(ClientSocket, Data, State),
            ?MODULE:fin(close, State)
    end.

bind(_, State)->
    lager:error("BIND. Not supported"),
    ?MODULE:fin(close, State).
udp_associate(_, State)->
    lager:error("UDP_ASSOCIATE. Not supported"),
    ?MODULE:fin(close, State).

transfer_data(_, State)->
    {next_state, transfer_data, State}.

-spec(fin(Event:: term(), State :: #state{}) ->
    {stop, normal, NewState :: #state{}}).
fin(_Reason, #state{cln_socket = ClientSocket}=State) ->
    lager:info("Socket ~p. Fin state.", [ClientSocket]),
    gen_tcp:close(ClientSocket),
    {stop, normal, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_event/[2,3], the instance of this function with
%% the same name as the current state name StateName is called to
%% handle the event.
%% @end
%%--------------------------------------------------------------------
-spec(authentication(Event :: term(), From :: {pid(), term()}, State :: #state{}) ->
    {next_state, NextStateName :: atom(), NextState :: #state{}} |
    {next_state, NextStateName :: atom(), NextState :: #state{}, timeout() | hibernate} |
    {reply, Reply, NextStateName :: atom(), NextState :: #state{}} |
    {reply, Reply, NextStateName :: atom(), NextState :: #state{}, timeout() | hibernate} |
    {stop, Reason :: normal | term(), NewState :: #state{}} |
    {stop, Reason :: normal | term(), Reply :: term(), NewState :: #state{}}).
authentication(_Event, _From, #state{cln_socket = _Socket} = State) ->
    Reply = ok,
    {reply, Reply, authentication, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event.
%% @end
%%--------------------------------------------------------------------
-spec(handle_event(Event :: term(), StateName :: atom(), StateData :: #state{}) ->
    {next_state, NextStateName :: atom(), NewStateData :: #state{}} |
    {next_state, NextStateName :: atom(), NewStateData :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term(), NewStateData :: #state{}}).
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/[2,3], this function is called
%% to handle the event.
%% @end
%%--------------------------------------------------------------------
-spec(handle_sync_event(Event :: term(), From :: {pid(), Tag :: term()}, StateName :: atom(), StateData :: term()) ->
    {reply, Reply :: term(), NextStateName :: atom(), NewStateData :: term()} |
    {reply, Reply :: term(), NextStateName :: atom(), NewStateData :: term(), timeout() | hibernate} |
    {next_state, NextStateName :: atom(), NewStateData :: term()} |
    {next_state, NextStateName :: atom(), NewStateData :: term(),  timeout() | hibernate} |
    {stop, Reason :: term(), Reply :: term(), NewStateData :: term()} |
    {stop, Reason :: term(), NewStateData :: term()}).
handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    {reply, Reply, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it receives any
%% message other than a synchronous or asynchronous event
%% (or a system message).
%% @end
%%--------------------------------------------------------------------
-spec(handle_info(Info :: term(), StateName :: atom(), StateData :: term()) ->
    {next_state, NextStateName :: atom(), NewStateData :: term()} |
    {next_state, NextStateName :: atom(), NewStateData :: term(), timeout() | hibernate} |
    {stop, Reason :: normal | term(), NewStateData :: term()}).
handle_info({tcp, ClientSocket,  <<5, _/binary>> = BinData}, StateName, #state{cln_socket=ClientSocket} = State) ->
    ?MODULE:StateName({ok, BinData}, State);

handle_info({tcp, ClientSocket,  BinData}, transfer_data, #state{cln_socket=ClientSocket,trg_socket = TargetSocket, is_conect_set = true} = State) ->
    send_data(TargetSocket, BinData, State),
    {next_state, transfer_data, State};

handle_info({tcp, ClientSocket,  BinData}, _StateName, #state{cln_socket=ClientSocket,trg_socket = TargetSocket,is_conect_set = true} = State) ->
    send_data(TargetSocket, BinData, State),
    {next_state, transfer_data, State};

handle_info({tcp, TargetSocket, BinData}, StateName, #state{trg_socket = TargetSocket, cln_socket=ClientSocket} = State) ->
    send_data(ClientSocket, BinData, State),
    {next_state, StateName, State};

handle_info({tcp_closed, _Socket}, _StateName, State) ->
    lager:info("Socket ~p. Msg: tcp_closed", [_Socket]),
    ?MODULE:fin(close, State);

handle_info({tcp_error, Socket, Reason}, _StateName, State) ->
    lager:info("Socket ~p . Msg: tcp_error Reason: ~p", [Socket, Reason]),
    ?MODULE:fin(close, State);

handle_info(timeout, _StateName, State) ->
    ?MODULE:fin(close, State);

handle_info(_Info, StateName, State) ->
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%% @end
%%--------------------------------------------------------------------
-spec(terminate(Reason :: normal | shutdown | {shutdown, term()}
              | term(), StateName :: atom(), StateData :: term()) -> term()).
terminate(_Reason, _StateName, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
-spec(code_change(OldVsn :: term() | {down, term()}, StateName :: atom(), StateData :: #state{}, Extra :: term()) ->
    {ok, NextStateName :: atom(), NewStateData :: #state{}}).
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec(send_data(SocketTo :: port(), BinData :: binary(), State :: #state{}) ->
  {ok, normal}).
send_data(SocketTo, BinData, State) ->
    case gen_tcp:send(SocketTo, BinData) of
        ok ->
            {ok, normal};
        {error, _Error} ->
            lager:error("Socket ~p . error send data.", [SocketTo]),
            ?MODULE:fin(close, State)
    end.