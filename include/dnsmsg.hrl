-define(IS_REFERRAL(RR), (
    element(2, RR) =:= referral orelse
    element(2, RR) =:= addressless_referral
)).
