

ans,unans=sr( IP(dst="192.168.*.1-10")/UDP(dport=0) )
ans.summary( lambda(s,r) : r.sprintf("%IP.src% is alive") )
