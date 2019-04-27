 %% When extra resource record types are specified, this
%% module will be replaced by a new one compiled by dnslib
-module(dnsrr_types).

-export([
    atom/0,
    value/0,
    masterfile_token/0
]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

atom() -> #{
    a      => dnsrr_a,
    aaaa   => dnsrr_aaaa,
    all    => dnsrr_all,
    axfr   => dnsrr_axfr,
    cname  => dnsrr_cname,
    dnskey => dnsrr_dnskey,
    ds     => dnsrr_ds,
    hinfo  => dnsrr_hinfo,
    ixfr   => dnsrr_ixfr,
    maila  => dnsrr_maila,
    mailb  => dnsrr_mailb,
    mb     => dnsrr_mb,
    md     => dnsrr_md,
    mf     => dnsrr_mf,
    mg     => dnsrr_mg,
    minfo  => dnsrr_minfo,
    mr     => dnsrr_mr,
    mx     => dnsrr_mx,
    naptr  => dnsrr_naptr,
    ns     => dnsrr_ns,
    nsec   => dnsrr_nsec,
    null   => dnsrr_null,
    opt    => dnsrr_opt,
    ptr    => dnsrr_ptr,
    rrsig  => dnsrr_rrsig,
    soa    => dnsrr_soa,
    srv    => dnsrr_srv,
    sshfp  => dnsrr_sshfp,
    txt    => dnsrr_txt,
    uri    => dnsrr_uri,
    wks    => dnsrr_wks
}.

value() -> #{
    1   => dnsrr_a,
    2   => dnsrr_ns,
    3   => dnsrr_md,
    4   => dnsrr_mf,
    5   => dnsrr_cname,
    6   => dnsrr_soa,
    7   => dnsrr_mb,
    8   => dnsrr_mg,
    9   => dnsrr_mr,
    10  => dnsrr_null,
    11  => dnsrr_wks,
    12  => dnsrr_ptr,
    13  => dnsrr_hinfo,
    14  => dnsrr_minfo,
    15  => dnsrr_mx,
    16  => dnsrr_txt,
    28  => dnsrr_aaaa,
    33  => dnsrr_srv,
    35  => dnsrr_naptr,
    41  => dnsrr_opt,
    43  => dnsrr_ds,
    44  => dnsrr_sshfp,
    46  => dnsrr_rrsig,
    47  => dnsrr_nsec,
    48  => dnsrr_dnskey,
    251 => dnsrr_ixfr,
    252 => dnsrr_axfr,
    253 => dnsrr_mailb,
    254 => dnsrr_maila,
    255 => dnsrr_all,
    256 => dnsrr_uri
}.

masterfile_token() -> #{
    "a"      => dnsrr_a,
    "aaaa"   => dnsrr_aaaa,
    "cname"  => dnsrr_cname,
    "dnskey" => dnsrr_dnskey,
    "ds"     => dnsrr_ds,
    "hinfo"  => dnsrr_hinfo,
    "mb"     => dnsrr_mb,
    "md"     => dnsrr_md,
    "mf"     => dnsrr_mf,
    "mg"     => dnsrr_mg,
    "minfo"  => dnsrr_minfo,
    "mr"     => dnsrr_mr,
    "mx"     => dnsrr_mx,
    "naptr"  => dnsrr_naptr,
    "ns"     => dnsrr_ns,
    "nsec"   => dnsrr_nsec,
    "ptr"    => dnsrr_ptr,
    "rrsig"  => dnsrr_rrsig,
    "soa"    => dnsrr_soa,
    "srv"    => dnsrr_srv,
    "sshfp"  => dnsrr_sshfp,
    "txt"    => dnsrr_txt,
    "uri"    => dnsrr_uri,
    "wks"    => dnsrr_wks
}.


-ifdef(EUNIT).
builtin_modules_sanity_test() ->
    Builtin = dnsrr:builtin(),
    CheckFn = fun ({_, FunMod}) -> not lists:member(FunMod, Builtin) end,
    [] = lists:filter(CheckFn, maps:to_list(atom())),
    [] = lists:filter(CheckFn, maps:to_list(value())),
    [] = lists:filter(CheckFn, maps:to_list(masterfile_token())),
    TakeFn = fun ({_, FunMod}, FunAcc) -> lists:delete(FunMod, FunAcc) end,
    [] = lists:foldl(TakeFn, Builtin, maps:to_list(atom())),
    [] = lists:foldl(TakeFn, Builtin, maps:to_list(value())).
-endif.
