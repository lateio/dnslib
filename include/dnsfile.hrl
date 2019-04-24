-record(dnsfile, {
    state=ok,
    resources=[]  :: [dnslib:resource()],
    path          :: string(),
    included_from :: 'undefined' | string()
}).
