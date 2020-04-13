# Origin:  https://github.com/matejzero/logstash-grok-patterns/blob/master/dovecot.grok
# dovecot variables (fields name): https://wiki.dovecot.org/Variables
#### Dovecot standard presets
#RIP_LIP rip=%{IP:clientip}, lip=%{IP:logip}
DOVECOT_HEADER %{PROG:process}-login: %{DATA:eventmsg}:
EVENTS (Aborted )?[Ll]ogin|(Dis)?[Cc]onnect(ed)?|Connection closed|started proxying|(dis)?connecting|\w+\s\w+|%{WORD}
ENCRYPT_PROTO (TLS(v\d)?|SSL(v\d)?|STARTTLS|secured)
#LMTP lmtp
DOVECOT_PREFIX (?:%{SYSLOGTIMESTAMP:datetime}|%{TIMESTAMP_ISO8601:datetime}) (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:loghost} %{PROG:logtype}:

# Email
#EMAILADDRESSPART [a-zA-Z0-9_.+-=:]+
#USEROREMAIL %{USERNAME:loginuser}(@%{HOSTNAME:loginDomain})?
USEROREMAIL %{USERNAME}(@%{HOSTNAME})?
RELAYSERVICE proxy


#### LOGINS
# Successful logins pop3/imap
#Oct 19 14:14:38 host dovecot: pop3-login: Login: user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, mpid=8056, secured, session=<QWvifIcOtQBUFOyV>
#Oct 19 14:14:38 host dovecot: pop3-login: Login: user=<username@domain.com>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, mpid=8056, secured, session=<QWvifIcOtQBUFOyV>
DOVECOT_LOGIN %{PROG:process}-login: %{EVENTS:event}: user=<(%{USEROREMAIL:loginuser})?>, method=%{WORD:authmethod}, rip=%{IP:clientip}, lip=%{IP:logip}, mpid=%{NUMBER:pid}(, %{ENCRYPT_PROTO:ciphers})?, session=<%{DATA:session}>

#### DISCONNECTS
# IMAP/POP3 successful logout
#Oct 19 14:14:38 host dovecot: imap(username): Disconnected: Logged out in=93 out=956
#Oct 19 14:14:38 host dovecot: pop3(username): Disconnected: Logged out top=0/0, retr=0/0, del=0/0, size=0
#Oct 19 14:14:38 host dovecot: imap(username): Disconnected: Disconnected in IDLE in=415 out=19066
#Oct 19 14:14:38 host dovecot: imap(username): Disconnected: Disconnected in APPEND (1 msgs, 0 secs, 0/215477 bytes) in=3166 out=144312
#Oct 19 14:14:38 host dovecot: pop3(username): Connection closed: Connection reset by peer top=0/0, retr=2/82331, del=6/168, size=50085176
#Oct 19 14:14:38 host dovecot: imap(username): Connection closed in=4573 out=47788
#Oct 19 14:14:38 host dovecot: imap(username): Disconnected for inactivity in=687 out=10791

DOVECOT_DISCONNECT1 %{PROG:process}\(%{USERNAME:loginuser}\): %{EVENTS:event}: (?<eventmsg>%{DATA} (in=%{NONNEGINT:outbytes} out=%{NONNEGINT:inbytes}|top=%{NUMBER}/%{NUMBER}, retr=%{NUMBER}/%{NUMBER}, del=%{NUMBER}/%{NUMBER}, size=%{NUMBER:msgsize}))
#Oct 19 14:14:38 host dovecot: imap(username): Connection closed in=4573 out=47788
DOVECOT_DISCONNECT2 %{PROG:process}\(%{USERNAME:loginuser}\): %{EVENTS:event} (?<eventmsg>(in=%{NONNEGINT:outbytes} out=%{NONNEGINT:inbytes}|top=%{NUMBER}/%{NUMBER}, retr=%{NUMBER}/%{NUMBER}, del=%{NUMBER}/%{NUMBER}, size=%{NUMBER:msgsize}))
#Oct 19 14:14:38 host dovecot: imap(username): Disconnected for inactivity in=687 out=10791
DOVECOT_DISCONNECT3 %{PROG:process}\(%{USERNAME:loginuser}\): %{EVENTS:event} (?<eventmsg>%{DATA} (in=%{NONNEGINT:outbytes} out=%{NONNEGINT:inbytes}|top=%{NUMBER}/%{NUMBER}, retr=%{NUMBER}/%{NUMBER}, del=%{NUMBER}/%{NUMBER}, size=%{NUMBER:msgsize}))
# Authentation failed
#Oct 19 14:14:38 host dovecot: imap-login: Disconnected (auth failed, 1 attempts in 4 secs): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, secured, session=<afeKFIcOYgAFPe0N>
#Oct 19 14:14:38 host dovecot: pop3-login: Aborted login (auth failed, 1 attempts): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5
#Oct 19 14:14:38 host dovecot: pop3-login: Aborted login (auth failed, 1 attempts): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, TLS
#Oct 19 14:14:38 host dovecot: pop3-login: Aborted login (auth failed, 1 attempts): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, session=<afeKFIcOYgAFPe0N>
#Oct 19 14:14:38 host dovecot: pop3-login: Aborted login (auth failed, 1 attempts): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, secured, session=<23hKXMAPuwBZ1MSq>
DOVECOT_DISCONNECT4 %{PROG:process}-login: %{EVENTS:event} \(%{DATA:eventmsg}\): user=<(%{USEROREMAIL:loginuser})?>, method=%{WORD:authmethod}, rip=%{IP:clientip}, lip=%{IP:logip}, %{ENCRYPT_PROTO:ciphers}, session=<%{DATA:session}>
# No auth attempt
#Oct 19 14:14:38 host dovecot: imap-login: Disconnected (no auth attempts in 0 secs): user=<>, rip=2.2.2.2, lip=5.5.5.5, TLS handshaking, session=<ssjRzuwPIwBZ1Ck5>
#Oct 19 14:14:38 host dovecot: pop3-login: Disconnected (no auth attempts): rip=2.2.2.2, lip=5.5.5.5, TLS handshaking: SSL_accept() failed: error:150760FC:SSL routines:SSL23_GET_CLIENT_HELLO:unknown protocol
#Oct 19 14:14:38 host dovecot: pop3-login: Disconnected (no auth attempts in 0 secs): user=<>, rip=2.2.2.2, lip=5.5.5.5, TLS handshaking: SSL_accept() failed: error:140760FC:SSL routines:SSL23_GET_CLIENT_HELLO:unknown protocol, session=<N296hewPSgAueh8K>
DOVECOT_DISCONNECT5 %{PROG:process}-login: %{EVENTS:event}(%{DATA})? \(%{DATA:eventmsg}\): rip=%{IP:clientip}, lip=%{IP:logip}, %{ENCRYPT_PROTO:ciphers}\s*%{GREEDYDATA:eventmsg}
DOVECOT_DISCONNECT5_BIS %{PROG:process}-login: %{EVENTS:event}(%{DATA})? \(%{DATA:eventmsg}\):( user=<>,)? rip=%{IP:clientip}, lip=%{IP:logip}, %{ENCRYPT_PROTO:ciphers}(\,|:)?( %{DATA:eventmsg},)?( session=<%{DATA:session}>)?
#Oct 19 14:14:38 host dovecot: pop3-login: Disconnected (no auth attempts): rip=2.2.2.2, lip=5.5.5.5, TLS handshaking: SSL_accept() failed: error:150760FC:SSL routines:SSL23_GET_CLIENT_HELLO:unknown protocol
#Oct 19 14:14:38 host dovecot: pop3-login: Aborted login (no auth attempts in 0 secs): user=<>, rip=2.2.2.2, lip=5.5.5.5, session=<Q4nfkMAPTQDBAhKu>
DOVECOT_DISCONNECT6 %{PROG:process}-login: %{EVENTS:event} \(%{DATA:eventmsg}\): (user=<(%{USEROREMAIL:loginuser})?>, )?rip=%{IP:clientip}, lip=%{IP:logip}(, session=<%{DATA:session}>)?(, %{GREEDYDATA:eventmsg})?
DOVECOT_DISCONNECT (%{DOVECOT_DISCONNECT1}|%{DOVECOT_DISCONNECT2}|%{DOVECOT_DISCONNECT3}|%{DOVECOT_DISCONNECT4}|%{DOVECOT_DISCONNECT5}|%{DOVECOT_DISCONNECT5_BIS}|%{DOVECOT_DISCONNECT6})
### PROXY
# Started proxying
#Oct 19 14:14:38 host dovecot: imap-login: proxy(username): started proxying to 2.2.2.2:143: user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, secured, session=<GKEBFAwQMgDBAgFf>
#Oct 19 14:14:38 host dovecot: pop3-login: proxy(username): started proxying to 2.2.2.2:110: user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, session=<udMDFAwQWQDU6/2a>
#Oct 19 14:14:38 host dovecot: imap-login: proxy(username): started proxying to 2.2.2.2:143: user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, TLS, session=<LGL0EwwQOQBOmTSo>
DOVECOT_PROXY1 %{PROG:process}-login: %{RELAYSERVICE:relayservice}\(%{USEROREMAIL:loginuser}\): %{EVENTS:event} to %{IPORHOST:relayhost}:%{POSINT:relayport}: user=<(%{USERNAME}(@%{HOSTNAME})?)?>, method=%{WORD:authmethod}, rip=%{IP:clientip}, lip=%{IP:logip}(, %{ENCRYPT_PROTO:ciphers})?, session=<%{DATA:session}>
# Disconnecting
#Oct 19 14:14:38 host dovecot: pop3-login: proxy(username): disconnecting 2.2.2.2 (Disconnected by server): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, TLS, session=<gg7JEwwQ6QDBTZ2t>
#Oct 19 14:14:38 host dovecot: pop3-login: proxy(username): disconnecting 2.2.2.2 (Disconnected by server): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, session=<9J/3EwwQFwDZSF8F>
#Oct 19 14:14:38 host dovecot: imap-login: proxy(username): disconnecting 2.2.2.2 (Disconnected by server): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, secured, session=<GKEBFAwQMgDBAgFf>
#Oct 19 14:14:38 host dovecot: imap-login: proxy(username): disconnecting 2.2.2.2 (Disconnected by client: Connection reset by peer): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, TLS, session=<tk+T3O4PowDULq55>
#Oct 19 14:14:38 host dovecot: pop3-login: proxy(username@example.com): disconnecting 2.2.2.2 (Disconnected by server): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, session=<9J/3EwwQFwDZSF8F>
DOVECOT_PROXY2 %{PROG:process}-login: %{RELAYSERVICE:relayservice}\(%{USEROREMAIL:loginuser}\): %{EVENTS:event} %{IPORHOST} \(%{DATA:eventmsg}\): user=<(%{USERNAME}(@%{HOSTNAME})?)?>, method=%{WORD:authmethod}, rip=%{IP:clientip}, lip=%{IP:logip}(, (session=<%{DATA:session}>|%{ENCRYPT_PROTO:ciphers}, session=<%{DATA:session}>|%{ENCRYPT_PROTO:ciphers}))?
DOVECOT_PROXY3 %{PROG:process}-login: %{RELAYSERVICE:relayservice}\(%{USEROREMAIL:loginuser}\): %{WORD:event} %{IP:relayip}
DOVECOT_PROXY (%{DOVECOT_PROXY1}|%{DOVECOT_PROXY2}|%{DOVECOT_PROXY3})

### EXCEEDED
# Max number of connections is exceeded
#Oct 19 14:14:38 host dovecot: imap-login: Maximum number of connections from user+IP exceeded (mail_max_userip_connections=50): user=<username>, method=PLAIN, rip=2.2.2.2, lip=5.5.5.5, secured, session=<at1XQPAPJABUFPIj>
DOVECOT_EXCEEDED %{PROG:process}-login: %{DATA:event} \(%{DATA:eventmsg}\): user=<(%{USEROREMAIL:loginuser})?>, method=%{WORD:authmethod}, rip=%{IP:clientip}, lip=%{IP:logip}(, (session=<%{DATA:session}>|%{ENCRYPT_PROTO:ciphers}, session=<%{DATA:session}>|%{ENCRYPT_PROTO:ciphers}))?

### LMTP logs
#Oct 19 14:14:38 host dovecot: lmtp(32352): Disconnect from local: Successful quit
#Oct 19 14:14:38 host dovecot: lmtp(32347): Connect from local
#Oct 19 14:14:38 host dovecot: lmtp(username): iUi8BBUI2FRbfgAAA15QOA: msgid=<E1YKcnl-0001q3-UM@example.com>: saved mail to INBOX
DOVECOT_LMTP %{PROG:process}\((%{POSINT:pid}|%{USERNAME:loginuser})\): (%{WORD:session}: )?((msgid=<%{DATA:msgid}>:)|%{EVENTS:event})?%{GREEDYDATA:eventmsg}

### Indexer
#Oct 19 14:14:38 host dovecot: indexer-worker(username): Indexed 10 messages in mail/Sent Messages
DOVECOT_INDEXER %{PROG:process}-worker\(%{USERNAME:loginuser}\): (?<event>Indexed) %{NUMBER:msgcount} %{GREEDYDATA:eventmsg}

#DOVECOT (%{DOVECOT_LOGIN}|%{DOVECOT_DISCONNECT}|%{DOVECOT_PROXY}|%{DOVECOT_INDEXER}|%{DOVECOT_LMTP}|%{DOVECOT_EXCEEDED})
DOV %{DOVECOT_PREFIX} (?:%{DOVECOT_LOGIN}|%{DOVECOT_DISCONNECT}|%{DOVECOT_PROXY}|%{DOVECOT_INDEXER}|%{DOVECOT_LMTP}|%{DOVECOT_EXCEEDED})
