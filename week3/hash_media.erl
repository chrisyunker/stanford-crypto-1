#!/usr/bin/env escript

%%! -sname crypto

main(Filename) ->
    io:format("compute hash for file: ~p~n", [Filename]),
    {ok, Bin} = file:read_file(Filename),
    io:format("file size: ~p~n", [size(Bin)]),
    Blocks = segment(Bin),
    io:format("file will be broken into ~p blocks~n", [length(Blocks)]),

    {H0, HBlocks} = hash(Blocks),
    io:format("H0 tag: ~s~n", [to_hex(H0)]),

    io:format("verify blocks....~n", []),
    verify(H0, HBlocks),
    io:format("blocks are verified~n", []).

verify(Hash, [H | T]) ->
    Hash = crypto:hash(sha256, H),
    Block = size(H) - 32,
    <<_:Block/binary, Hash2/binary>> = H,
    verify(Hash2, T);
verify(_Hash, []) ->
    ok.

to_hex(Bin) ->
    to_hex(Bin, "").
to_hex(<<V:1/binary,R/binary>>, Acc) ->
    VB = binary:decode_unsigned(V, little),
    H0 = VB band 240,
    H = H0 bsr 4,
    L = VB band 15,
    to_hex(R, Acc ++ c(H) ++ c(L));
to_hex(<<>>, Acc) ->
    Acc.

c(0) -> "0";
c(1) -> "1";
c(2) -> "2";
c(3) -> "3";
c(4) -> "4";
c(5) -> "5";
c(6) -> "6";
c(7) -> "7";
c(8) -> "8";
c(9) -> "9";
c(10) -> "a";
c(11) -> "b";
c(12) -> "c";
c(13) -> "d";
c(14) -> "e";
c(15) -> "f".

hash(Data) ->
    hash(lists:reverse(Data), undef, []).
hash([Block | Rest], PrevHash, Acc) ->
    Block1 = case PrevHash of
        undef ->
            Block;
        _ ->
            <<Block/binary, PrevHash/binary>>
    end,
    Hash = crypto:hash(sha256, Block1),
    hash(Rest, Hash, [Block1 | Acc]);
hash([], PrevHash, Acc) ->
    {PrevHash, Acc}.

segment(Bin) ->
    segment(Bin, []).
segment(<<H:1024/binary,T/binary>>, Acc) ->
    segment(T, [H | Acc]);
segment(<<H/binary>>, Acc) ->
    lists:reverse([H | Acc]);
segment(<<>>, Acc) ->
    lists:reverse(Acc).


