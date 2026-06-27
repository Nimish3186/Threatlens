# test_parser.py

from parsers.linux_parser import parse_syslog_line, parse_apache_line

test_lines = [
    "Jun 27 10:15:32 myserver sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2",
    "Jun 27 10:20:11 myserver sudo[5678]: john : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
    "Jun  7 09:00:01 myserver CRON[999]: (root) CMD (/usr/lib/cron/run-crons)",
    "not a real log line !!!",
]
for line in test_lines:
    result = parse_syslog_line(line)
    print(result)
    print("---")