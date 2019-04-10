-record(dnsfile, {
    resources=[]  :: [dnslib:resource()],
    path          :: string(),
    included_from :: 'undefined' | string()
}).
