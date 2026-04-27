##! Lightweight port-scan detector.
##! A single source connecting to >= scan_threshold distinct destination ports
##! within scan_window seconds raises Notice::PortScan.

module IDS;

export {
    redef enum Notice::Type += { PortScan };

    const scan_threshold: count = 15 &redef;
    const scan_window: interval = 60sec &redef;
}

global ports_seen: table[addr] of set[port] &create_expire = scan_window;
global already_alerted: set[addr] &create_expire = 1hr;

event connection_attempt(c: connection)
    {
    local src = c$id$orig_h;
    local dst_p = c$id$resp_p;

    if ( src !in ports_seen )
        ports_seen[src] = set();
    add ports_seen[src][dst_p];

    if ( |ports_seen[src]| >= scan_threshold && src !in already_alerted )
        {
        add already_alerted[src];
        NOTICE([$note=PortScan,
                $src=src,
                $msg=fmt("Port scan: %s contacted %d distinct ports", src, |ports_seen[src]|),
                $sub=fmt("count=%d window=%s", |ports_seen[src]|, scan_window),
                $identifier=cat(src)]);
        }
    }
