
create table log (ldate date,ltime time,username char (30),userip char (16),bytein integer (10),byteout integer (10),service char (8), host char(255), hostport integer (10), url char (255) );

create index idate on log (ldate);
create index iusername on log (username);
create index iuserip on log (userip);
create index ihost on log (host);

create table services (port integer(10),service char(100),description char (100)); 

INSERT INTO services values (80,'PROXY', 'Access to Web Server');
INSERT INTO services values (21,'PROXY', 'Access to Ftp Server via HTTP proxy');
INSERT INTO services values (5190,'PROXY', 'Access to ICQ via HTTP proxy');
INSERT INTO services values (0, 'POP3P', 'Received Mail via POP3');
INSERT INTO services values (0,'FTPPR', 'Access to Ftp server via FTP proxy');
INSERT INTO services values (0,'SOCKS4', 'Access to external server via Socks v4');
INSERT INTO services values (0,'SOCKS5', 'Access to external server via Socks v5');
INSERT INTO services values (0,'TCPPM', 'Access to external server via TCP mapping');
INSERT INTO services values (0,'UDPPM', 'Access to external server via UDP mapping');
INSERT INTO services values (0, 0, NULL, 'Unknown');


