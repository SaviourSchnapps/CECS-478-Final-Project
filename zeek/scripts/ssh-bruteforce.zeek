##! SSH brute-force detector.
##! When a source produces >= ssh_fail_threshold failed SSH auth attempts
##! against the same destination within ssh_window, raise Notice::SSHBruteForce.

module IDS;

export {
    redef enum Notice::Type += { SSHBruteForce };

    const ssh_fail_threshold: count = 5 &redef;
    const ssh_window: interval = 5min &redef;
}

type SSHKey: record {
    src: addr;
    dst: addr;
};

global ssh_fails: table[SSHKey] of count &default = 0 &create_expire = ssh_window;
global ssh_alerted: set[SSHKey] &create_expire = 1hr;

event ssh_auth_failed(c: connection)
    {
    local k = SSHKey($src=c$id$orig_h, $dst=c$id$resp_h);
    ++ssh_fails[k];

    if ( ssh_fails[k] >= ssh_fail_threshold && k !in ssh_alerted )
        {
        add ssh_alerted[k];
        NOTICE([$note=SSHBruteForce,
                $conn=c,
                $src=k$src,
                $msg=fmt("SSH brute-force: %s -> %s, %d failed attempts", k$src, k$dst, ssh_fails[k]),
                $sub=fmt("fails=%d window=%s", ssh_fails[k], ssh_window),
                $identifier=fmt("%s-%s", k$src, k$dst)]);
        }
    }
