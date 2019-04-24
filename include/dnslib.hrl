-define(DOMAIN_MAX_OCTETS, 255).
-define(MAX_TTL, 16#7FFFFFFF).

% Access dnslib:resource() fields
-define(RESOURCE_DOMAIN(Resource), element(1, Resource)).
-define(RESOURCE_TYPE(Resource),   element(2, Resource)).
-define(RESOURCE_CLASS(Resource),  element(3, Resource)).
-define(RESOURCE_TTL(Resource),    element(4, Resource)).
-define(RESOURCE_DATA(Resource),   element(5, Resource)).

% Access dnslib:question() fields
-define(QUESTION_DOMAIN(Question), ?RESOURCE_DOMAIN(Question)).
-define(QUESTION_TYPE(Question),   ?RESOURCE_TYPE(Question)).
-define(QUESTION_CLASS(Question),  ?RESOURCE_CLASS(Question)).

% dnslib:resource() and dnslib:question() guards
-define(IS_RESOURCE(Record),   (is_tuple(Record) andalso tuple_size(Record) =:= 5)).
-define(IS_QUESTION(Question), (is_tuple(Question) andalso tuple_size(Question) =:= 3)).
