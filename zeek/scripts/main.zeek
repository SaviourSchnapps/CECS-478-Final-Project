##! Entry script — enables JSON logging and loads all detectors.

@load base/frameworks/notice
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/ssh

@load ./port-scan.zeek
@load ./ssh-bruteforce.zeek
@load ./dos-detect.zeek

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
