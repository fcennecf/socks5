erl -sname socks_srv \
    -pa ./deps/*/ebin/ -pa ./ebin \
    -config ./priv/socksv5.config  \
    -s lager \
    -eval "application:start(socksv5)."
