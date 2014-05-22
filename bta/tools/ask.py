# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

def ask(q,ans):
    lowans = map(str.lower, ans)
    req = "{0} ({1}) ".format(q,"/".join(lowans))
    while True:
        r = raw_input(req).lower().strip()
        if r in ans:
            return r
