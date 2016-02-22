# Connection: localhost
# Host: 127.0.0.1
# Saved: 2004-04-09 18:53:52
# 
# Host: 127.0.0.1
# Database: 3proxy
# Table: 'log'
# 
CREATE TABLE `log` (
  `time` datetime NOT NULL default '0000-00-00 00:00:00',
  `bytesin` int(11) NOT NULL default '0',
  `bytesout` int(11) NOT NULL default '0',
  `username` varchar(20) NOT NULL default '',
  `service` varchar(7) NOT NULL default '',
  `host` varchar(100) NOT NULL default '',
  `port` int(11) NOT NULL default '0',
  `url` varchar(255) NOT NULL default ''
) TYPE=MyISAM; 

CREATE TABLE `services` (
  `startport` int(11) NOT NULL default '0',
  `endport` int(11) NOT NULL default '0',
  `service` varchar(100) NOT NULL default '',
  `description` varchar(100) NOT NULL default ''
) TYPE=MyISAM; 

CREATE TABLE `timelimit` (
  `datefrom` datetime NOT NULL default '0000-00-00 00:00:00',
  `dateto` datetime NOT NULL default '0000-00-00 00:00:00'
) TYPE=MyISAM; 

INSERT INTO services (80, 80, NULL, 'Access to Web Server');

INSERT INTO services (443, 443, NULL, 'Secure Access to Web Server');

INSERT INTO services (3128, 3128, NULL, 'Access to Web server via external Proxy');
INSERT INTO services (1080, 1080, NULL, 'Access to external SOCKS server');
INSERT INTO services (5190, 5190, NULL, 'Access to ICQ');
INSERT INTO services (6666, 6668, NULL, 'Access to IRC');

INSERT INTO services (119, 119, NULL, 'Access to news server');
INSERT INTO services (25, 25, NULL, 'Sent Mail');

INSERT INTO services (0, 0, 'POP3P', 'Received Mail');
INSERT INTO services (0, 0, 'SMTPP', 'Sent Mail');
INSERT INTO services (0, 0, 'TCPPM', 'Access to external server via TCP');
INSERT INTO services (0, 0, 'UDPPM', 'Access to external server via UDP');
INSERT INTO services (0, 0, 'PROXY', 'Access to external server via Proxy');
INSERT INTO services (0, 0, 'FTPPR', 'Access to external server via FTP Proxy');
INSERT INTO services (0, 0, 'ICQPR', 'Access to external server via ICQ Proxy');
INSERT INTO services (0, 0, 'SOCKS4', 'Access to external server via Socks v4');
INSERT INTO services (0, 0, 'SOCKS5', 'Access to external server via Socks v5');
INSERT INTO services (0, 0, 'DNSPR', 'Name resolution');
INSERT INTO services (0, 0, NULL, 'Unknown');


