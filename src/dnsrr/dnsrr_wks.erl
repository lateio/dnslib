% ------------------------------------------------------------------------------
%
% Copyright © 2018-2019, Lauri Moisio <l@arv.io>
%
% The ISC License
%
% Permission to use, copy, modify, and/or distribute this software for any
% purpose with or without fee is hereby granted, provided that the above
% copyright notice and this permission notice appear in all copies.
%
% THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL WARRANTIES
% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%
% ------------------------------------------------------------------------------
%
% This file implements operations required to work with
% DNS WKS records (RFC1034 and RFC1035).
-module(dnsrr_wks).

-behavior(dnsrr).
-export([
    masterfile_token/0,
    atom/0,
    value/0,
    class/0,
    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,
    to_binary/1,
    from_binary/1,
    valid_data/1
]).

-export([bitmap_to_ports/1,ports_to_bitmap/1]).

-define(MAX_BITMAP, 8192).

masterfile_token() -> "wks".
atom() -> wks.
value() -> 11.

class() -> [in].

masterfile_format() -> [token, token, token, '...'].


% As per RFC1010
protocol("icmp")        -> protocol(1);
protocol("igmp")        -> protocol(2);
protocol("ggp")         -> protocol(3);
protocol("st")          -> protocol(5);
protocol("tcp")         -> protocol(6);
protocol("ucl")         -> protocol(7);
protocol("egp")         -> protocol(8);
protocol("igp")         -> protocol(9);
protocol("bbn-rcc-mon") -> protocol(10);
protocol("nvp-ii")      -> protocol(11);
protocol("pup")         -> protocol(12);
protocol("argus")       -> protocol(13);
protocol("emcon")       -> protocol(14);
protocol("xnet")        -> protocol(15);
protocol("chaos")       -> protocol(16);
protocol("udp")         -> protocol(17);
protocol("mux")         -> protocol(18);
protocol("dcn-meas")    -> protocol(19);
protocol("hmp")         -> protocol(20);
protocol("prm")         -> protocol(21);
protocol("xns-idp")     -> protocol(22);
protocol("trunk-1")     -> protocol(23);
protocol("trunk-2")     -> protocol(24);
protocol("leaf-1")      -> protocol(25);
protocol("leaf-2")      -> protocol(26);
protocol("rdp")         -> protocol(27);
protocol("irtp")        -> protocol(28);
protocol("iso-tp4")     -> protocol(29);
protocol("netblt")      -> protocol(30);
protocol("mfe-nsp")     -> protocol(31);
protocol("merit-inp")   -> protocol(32);
protocol("sep")         -> protocol(33);
protocol("cftp")        -> protocol(62);
protocol("sat-expak")   -> protocol(64);
protocol("mit-subnet")  -> protocol(65);
protocol("rvd")         -> protocol(66);
protocol("ippc")        -> protocol(67);
protocol("sat-mon")     -> protocol(69);
protocol("ipcv")        -> protocol(71);
protocol("br-sat-mon")  -> protocol(76);
protocol("wb-mon")      -> protocol(78);
protocol("wb-expak")    -> protocol(79);
protocol(Int) when is_list(Int) ->
    case
        try list_to_integer(Int, 10)
        catch error:_ -> {error, {unrecognized_protocol, Int}}
        end
    of
        {error, _}=Tuple -> Tuple;
        Protocol -> protocol(Protocol)
    end;
protocol(Int) when is_integer(Int) ->
    {ok, Int}.


% As per RFC1010 (There are obviously a few more services/ports nowadays...)
port("rje", Bitmap)         -> port(5, Bitmap);
port("echo", Bitmap)        -> port(7, Bitmap);
port("discard", Bitmap)     -> port(9, Bitmap);
port("users", Bitmap)       -> port(11, Bitmap);
port("daytime", Bitmap)     -> port(13, Bitmap);
port("quote", Bitmap)       -> port(17, Bitmap); % obviously important
port("chargen", Bitmap)     -> port(19, Bitmap);
port("ftp-data", Bitmap)    -> port(20, Bitmap);
port("ftp", Bitmap)         -> port(21, Bitmap);
port("ssh", Bitmap)         -> port(22, Bitmap);
port("telnet", Bitmap)      -> port(23, Bitmap);
port("smtp", Bitmap)        -> port(25, Bitmap);
port("nsw-fe", Bitmap)      -> port(27, Bitmap);
port("msg-icp", Bitmap)     -> port(29, Bitmap);
port("msg-auth", Bitmap)    -> port(31, Bitmap);
port("dsp", Bitmap)         -> port(33, Bitmap);
port("time", Bitmap)        -> port(37, Bitmap);
port("rlp", Bitmap)         -> port(39, Bitmap);
port("graphics", Bitmap)    -> port(41, Bitmap);
port("nameserver", Bitmap)  -> port(42, Bitmap);
port("nicname", Bitmap)     -> port(43, Bitmap);
port("mpm-flags", Bitmap)   -> port(44, Bitmap);
port("mpm", Bitmap)         -> port(45, Bitmap);
port("mpm-snd", Bitmap)     -> port(46, Bitmap);
port("ni-ftp", Bitmap)      -> port(47, Bitmap);
port("login", Bitmap)       -> port(49, Bitmap);
port("la-maint", Bitmap)    -> port(51, Bitmap);
port("domain", Bitmap)      -> port(53, Bitmap);
port("isi-gl", Bitmap)      -> port(55, Bitmap);
port("ni-mail", Bitmap)     -> port(61, Bitmap);
port("via-ftp", Bitmap)     -> port(63, Bitmap);
port("tacacs-ds", Bitmap)   -> port(65, Bitmap);
port("bootps", Bitmap)      -> port(67, Bitmap);
port("bootpc", Bitmap)      -> port(68, Bitmap);
port("tftp", Bitmap)        -> port(69, Bitmap);
port("netrjs-1", Bitmap)    -> port(71, Bitmap);
port("netrjs-2", Bitmap)    -> port(72, Bitmap);
port("netrjs-3", Bitmap)    -> port(73, Bitmap);
port("netrjs-4", Bitmap)    -> port(74, Bitmap);
port("finger", Bitmap)      -> port(79, Bitmap);
port("http", Bitmap)        -> port(80, Bitmap);
port("hosts2-ns", Bitmap)   -> port(81, Bitmap);
port("mit-ml-dev", Bitmap0) ->
    {ok, Bitmap1} = port(83, Bitmap0),
    port(85, Bitmap1);
port("su-mit-tg", Bitmap)   -> port(89, Bitmap);
port("mit-dov", Bitmap)     -> port(91, Bitmap);
port("dcp", Bitmap)         -> port(93, Bitmap);
port("supdup", Bitmap)      -> port(95, Bitmap);
port("swift-rvf", Bitmap)   -> port(97, Bitmap);
port("tacnews", Bitmap)     -> port(98, Bitmap);
port("metagram", Bitmap)    -> port(99, Bitmap);
port("hostname", Bitmap)    -> port(101, Bitmap);
port("iso-tsap", Bitmap)    -> port(102, Bitmap);
port("x400", Bitmap)        -> port(103, Bitmap);
port("x400-snd", Bitmap)    -> port(104, Bitmap);
port("csnet-ns", Bitmap)    -> port(105, Bitmap);
port("rtelnet", Bitmap)     -> port(107, Bitmap);
port("pop-2", Bitmap)       -> port(109, Bitmap);
port("sunrpc", Bitmap)      -> port(111, Bitmap);
port("auth", Bitmap)        -> port(113, Bitmap);
port("sftp", Bitmap)        -> port(115, Bitmap);
port("uucp-path", Bitmap)   -> port(117, Bitmap);
port("nntp", Bitmap)        -> port(119, Bitmap);
port("erpc", Bitmap)        -> port(121, Bitmap);
port("ntp", Bitmap)         -> port(123, Bitmap);
port("locus-map", Bitmap)   -> port(125, Bitmap);
port("locus-con", Bitmap)   -> port(127, Bitmap);
port("pwdgen", Bitmap)      -> port(129, Bitmap);
port("cisco-fna", Bitmap)   -> port(130, Bitmap);
port("cisco-tna", Bitmap)   -> port(131, Bitmap);
port("cisco-sys", Bitmap)   -> port(132, Bitmap);
port("statsrv", Bitmap)     -> port(133, Bitmap);
port("ingres-net", Bitmap)  -> port(134, Bitmap);
port("loc-srv", Bitmap)     -> port(135, Bitmap);
port("profile", Bitmap)     -> port(136, Bitmap);
port("netbios-ns", Bitmap)  -> port(137, Bitmap);
port("netbios-dgm", Bitmap) -> port(138, Bitmap);
port("netbios-ssn", Bitmap) -> port(139, Bitmap);
port("emfis-data", Bitmap)  -> port(140, Bitmap);
port("emfis-cntl", Bitmap)  -> port(141, Bitmap);
port("bl-idm", Bitmap)      -> port(142, Bitmap);
port("sur-meas", Bitmap)    -> port(243, Bitmap);
port("link", Bitmap)        -> port(245, Bitmap);
port(Str, Bitmap) when is_list(Str) ->
    case
        try list_to_integer(Str, 10)
        catch error:_ -> {error, {unrecognized_port, Str}}
        end
    of
        {error, _}=Tuple -> Tuple;
        Port -> port(Port, Bitmap)
    end;
port(Int, _) when Int < 0; Int > (16#FFFF - 5) * 8 - 1  ->
    {error, {port_out_of_range, Int}};
port(Int, Bitmap) when is_integer(Int) ->
    % Figure out which byte the Int fits in.
    % If the bitmap is not long enough, expand it
    % and recurse
    case Int div 8 of
        Index when byte_size(Bitmap) =:= Index ->
            Byte = 16#80 bsr (Int rem 8),
            {ok, <<Bitmap/binary, Byte>>};
        Index when byte_size(Bitmap) =< Index ->
            Diff = (Index + 1) - byte_size(Bitmap),
            port(Int, <<Bitmap/binary, 0:(Diff*8)>>);
        ByteIndex ->
            Bit = 16#80 bsr (Int rem 8),
            StartOff = ByteIndex,
            <<Start:StartOff/binary, Byte, End/binary>> = Bitmap,
            {ok, <<Start/binary, (Byte bor Bit), End/binary>>}
    end.


ports([], Bitmap) ->
    {ok, Bitmap};
ports([Port|Rest], Bitmap0) ->
    case port(string:lowercase(Port), Bitmap0) of
        {ok, Bitmap1} -> ports(Rest, Bitmap1);
        {error, _}=Tuple -> Tuple
    end.


from_masterfile([Address0, Protocol0|Ports0]) ->
    case inet:parse_ipv4strict_address(Address0) of
        {ok, Address1} ->
            case protocol(string:lowercase(Protocol0)) of
                {error, Reason} -> {error, {invalid_protocol, Reason}};
                {ok, Protocol1} ->
                    case ports(Ports0, <<>>) of
                        {error, Reason} -> {error, {invalid_port, Reason}};
                        {ok, Ports1} -> {ok, {Address1, Protocol1, Ports1}}
                    end
            end;
        _ -> {error, invalid_address}
    end.


to_masterfile({Address, Protocol, Ports}) ->
    [
        inet:ntoa(Address),
        integer_to_list(Protocol)
    |lists:map(fun erlang:integer_to_list/1, bitmap_to_ports(Ports))].


to_binary({{B1, B2, B3, B4}, Protocol, Bitmap}) ->
    {ok, [B1, B2, B3, B4, Protocol, Bitmap]}.


from_binary(<<B1, B2, B3, B4, Protocol, Bitmap/binary>>) when byte_size(Bitmap) =< ?MAX_BITMAP ->
    {ok, {{B1, B2, B3, B4}, Protocol, Bitmap}}.


bitmap_to_ports(Bitmap) ->
    bitmap_to_ports(Bitmap, 0, []).


bitmap_to_ports(<<>>, _, Acc) ->
    lists:reverse(Acc);
bitmap_to_ports(<<Byte, Rest/binary>>, Index, Acc) ->
    bitmap_to_ports(Rest, Index+1, byte_to_ports(<<Byte>>, Index*8, Acc)).


byte_to_ports(<<>>, _, Acc) ->
    Acc;
byte_to_ports(<<1:1,Rest/bits>>, PortNo, Acc) ->
    byte_to_ports(Rest, PortNo+1, [PortNo|Acc]);
byte_to_ports(<<0:1,Rest/bits>>, PortNo, Acc) ->
    byte_to_ports(Rest, PortNo+1, Acc).


ports_to_bitmap(Ports) ->
    ports_to_bitmap(Ports, <<>>).


ports_to_bitmap([], Bitmap) ->
    Bitmap;
ports_to_bitmap([Port|Rest], Bitmap0)
when is_integer(Port), Port >= 0, Port =< 16#FFFF ->
    {ok, Bitmap1} = port(Port, Bitmap0),
    ports_to_bitmap(Rest, Bitmap1);
ports_to_bitmap([Port|Rest], Bitmap0) when is_list(Port) ->
    {ok, Bitmap1} = port(string:lowercase(Port), Bitmap0),
    ports_to_bitmap(Rest, Bitmap1).


valid_data({Address, Protocol, Bitmap})
when is_integer(Protocol), Protocol >= 0, Protocol =< 16#FF ->
    case dnsrr_a:valid_data(Address) of
        true -> is_binary(Bitmap) andalso byte_size(Bitmap) =< ?MAX_BITMAP;
        false -> false
    end.
