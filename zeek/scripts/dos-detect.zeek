##! Simple connection-flood detector.
##! Counts new connection attempts per source per dos_window.
##! Above dos_threshold the detector raises Notice::ConnFlood.

module IDS;

export {
    redef enum Notice::Type += { ConnFlood };

    const dos_threshold: count = 200 &redef;
    const dos_window: interval = 30sec &redef;
}

global conn_count: table[addr] of count &default = 0 &create_expire = dos_window;
global dos_alerted: set[addr] &create_expire = 1hr;

event new_connection(c: connection)
    {
    local src = c$id$orig_h;
    ++conn_count[src];

    if ( conn_count[src] >= dos_threshold && src !in dos_alerted )
        {
        add dos_alerted[src];
        NOTICE([$note=ConnFlood,
                $conn=c,
                $src=src,
                $msg=fmt("Connection flood: %s opened %d connections in %s",
                         src, conn_count[src], dos_window),
                $sub=fmt("count=%d window=%s", conn_count[src], dos_window),
                $identifier=cat(src)]);
        }
    }
