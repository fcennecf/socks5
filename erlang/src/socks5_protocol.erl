%%%-------------------------------------------------------------------
%%% @author klimontov
%%% @copyright (C) 2014, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 21. ноя 2014 8:29
%%%-------------------------------------------------------------------
-module(socks5_protocol).
-author("klimontov").

%% API
-export([decode/2,
         encode/2,
         encode/3,
         convert_addres_to_inet_format/2
        ]).

-type ip_type() :: ip4 | ip6 | domainname .

-spec(decode(TypeMsg :: atom(), Data ::binary()) ->
    {ok, {AuthCount :: integer(), LAuthTypes::list(integer())}} |
    {ok, {CommandType:: atom(),{IpType::ip_type(), {Address::binary(), Port::binary()}}}} |
    {error, decode_error}).
decode(authentication, <<5, AuthCount, AuthTypes:AuthCount/binary>>)->
    LAuthTypes = binary:bin_to_list(AuthTypes),
    {ok, {AuthCount, LAuthTypes}};

decode(handshake, <<5, CMD:8, 0, ATYP:8, BinAddrPort/binary >>) ->
    AddrPort = case ATYP of
        1 -> %IP V4 address: X'01'
            <<Address:32, Port/binary>> = BinAddrPort,
            {ip4, {<<Address:32>>, Port}};
        3 -> % DOMAINNAME: X'03'
            <<AddressDomainLen:8, AddressDomainBin:AddressDomainLen/binary, Port/binary>> = BinAddrPort,
            {domainname, {AddressDomainBin,Port }};
        4 -> % IP V6 address: X'04'
            %% TODO: Do not tested.
            lager:warning("TODO:  IP V6 address: X'04' Do not tested."),
            <<Address:128, Port/binary>> = BinAddrPort,
            {ip6, {<<Address:128>>, Port}}
    end,

    case lists:keysearch(CMD, 1, [{1, connect}, {2, bind}, {3, udp_associate}]) of
        false ->
            {error, decode_error};
        {value,{_,CmdType}}->
            {ok, {CmdType, AddrPort}}
    end;


decode(_TypeMsg, _DataBin)->
    {error, decode_error}.

-spec(encode( Message :: atom(), Data :: term()) ->
    binary()).
encode(authentication, {true, 0}) ->
    <<5,0>>;
encode(authentication, _) ->
    <<5,16#FF>>;

%o  X'04' Host unreachable
%o  X'08' Address type not supported
encode(connect,{ip6, Address, Port} ) ->
    <<5, 8, 0, 4, Address:128, Port/binary>>;
encode(connect,{domainname, Address, Port} ) ->
    <<5, 8, 0, 3, (byte_size(Address)):8, Address/binary, Port/binary>>;
encode(_Type, _Data)->
    <<>>.

-spec(encode( Message::atom(), {IpType::ip_type(), Address::binary(), Port::binary()}, Replay :: integer()) ->
    binary()).
encode(connect,{domainname, Address, Port}, Replay) ->
    <<5, Replay, 0, 3, (byte_size(Address)):8, Address/binary, Port/binary>>;
encode(connect, {ip4, Address, Port}, Replay ) ->
    <<5, Replay, 0, 1, Address/binary, Port/binary>>;
encode(connect, {ip6, Address, Port}, Replay ) ->
    <<5, Replay, 0, 4, Address/binary, Port/binary>>.

-spec(convert_addres_to_inet_format( AdrType::ip_type(), Address::binary()) ->
  term() | list()).
convert_addres_to_inet_format(AdrType, Address) when (AdrType =:= ip4) or
                                                     (AdrType =:= ip6)->
    list_to_tuple(binary_to_list(Address));
convert_addres_to_inet_format(domainname, Address)->
    binary_to_list(Address).