#!/usr/bin/perl
eval 'exec /usr/bin/perl -S $0 ${1+"$@"}'
    if $running_under_some_shell;
			# this emulates #! processing on NIH machines.
			# (remove #! line above if indigestible)

eval '$'.$1.'$2;' while $ARGV[0] =~ /^([A-Za-z_0-9]+=)(.*)/ && shift;
			# process any FOO=bar switches

$[ = 1;			# set array base to 1
$, = ' ';		# set output field separator
$\ = "\n";		# set output record separator

$scriptname = $ENVIRON{'SCRIPT_NAME'};
#for win32
$isql = ".\\isqlodbc.exe sqlite ";

#for unix
#isql="./isqlodbc sqlite " 

print "Content-Type: text/html; charset=koi8-r \n\n";
print "<HTML>\n<BODY>\n";

# query parse
$query_str = $ENVIRON{'QUERY_STRING'};
$n = (@querys = split(/&/, $query_str, 9999));
for ($i = 1; $i <= $n; $i++) {
    @data = split(/=/, $querys[$i], 9999);
    $qr{$data[1]} = $data[2];
}

printf "<FORM METHOD=PUT action=\"" . $scriptname . "?rep=1\">";
printf "datefrom:<INPUT name=\"datefrom\" value=\"2004-06-01\"> ";
printf "dateto:<INPUT name=\"dateto\" value=\"2004-07-30\"> <br>";
printf

  "<INPUT type=\"radio\" name=\"userid\" value=\"username\" checked> LOGIN user <br>";
printf

  "<INPUT type=\"radio\" name=\"userid\" value=\"userip\"> IP user  <br>";
printf "<INPUT type=\"hidden\" name=\"rep\" value=\"user\">";
printf "<INPUT type=\"submit\" value=\"Report\">";
printf '</FORM>';

#printf "query_str=%s\n<br>",query_str
#print  qr["rep"]

if ($qr{'rep'} eq 'user') {
    $cmd = $isql . " \"select " . $qr{'userid'} .

      ",sum(bytein),sum(byteout),sum(bytein+byteout) from log         where ldate > '"

      . $qr{'datefrom'} . "'  AND ldate < '" . $qr{'dateto'} . "' group by " .

      $qr{'userid'} . " order by sum(bytein+byteout) desc;\"";
    printf

      ' <table WIDTH=100%%  BORDER=1><tr><td><b>user</b></td> <td><b>bytein</b></td> <td><b>byteout</b> </td> <td> <b>bytesum</b></td></tr>';
    while ((($result = &Getline3($cmd, '|'),$getline_ok)) > 0) {
	@rt = split(/\|/, $result, 9999);
	printf

	  "<tr> <td><a href=\"%s?rep=host&datefrom=%s&dateto=%s&userid=%s&selectid=%s\"> %s <\\/a></td><td>%d</td><td>%d</td><td>%d</td></tr>",

	  
	$scriptname, $qr{'datefrom'}, $qr{'dateto'}, $qr{'userid'}, $rt[1],

	  $rt[1], $rt[2], $rt[3], $rt[4];
	$totalbytein = $totalbytein + $rt[2];
	$totalbyteout = $totalbyteout + $rt[3];
	$totalbytesum = $totalbytesum + $rt[4];
    }
    printf

      '<tr> <td><br>Total users</td> <td><br>%d</td> <td><br>%d</td>     <td><br>%d</td></tr> </table> ',

      $totalbytein, $totalbyteout, $totalbytesum;
    delete $opened{$cmd} && close($cmd);
}

if ($qr{'rep'} eq 'host') {
    $cmd = $isql .

      "\"select sum(bytein+byteout), sum(bytein), sum(byteout),host from log         where ldate > '"

      . $qr{'datefrom'} . "' AND ldate < '" . $qr{'dateto'} . "' AND " .

      $qr{'userid'} . " = '" . $qr{'selectid'} .

      "' group by host order by sum(bytein+byteout) desc;\"";

    printf '<center><b>Detail statistic for user: %s</b></center>',

      $qr{'selectid'};
    printf

      ' <table WIDTH=100%%  BORDER=1> <tr><td><b>sum byte</b></td> <td><b>bytein</b></td> <td><b>byteout</b></td><td><b>host</b></td></tr>';
    while ((($result = &Getline3($cmd, '|'),$getline_ok)) > 0) {
	@rt = split(/\|/, $result, 9999);
	printf '<tr><td>%d</td><td>%d</td><td>%d</td><td>%s</td></tr>',

	  $rt[1], $rt[2], $rt[3], $rt[4];
	$totalbytein = $totalbytein + $rt[1];
	$totalbyteout = $totalbyteout + $rt[2];
	$totalbytesum = $totalbytesum + $rt[3];
    }
    printf

      '<tr> <td><br>%d</td> <td><br>%d</td>     <td><br>%d</td><td><br>Total host</td></tr> </table> ',

      $totalbytein, $totalbyteout, $totalbytesum;
    printf ' </table> ';
    delete $opened{$cmd} && close($cmd);
}

printf ' </BODY> </HTML>';

# end BEGIN 

# decode urlencoded string

sub decode {
    local($text, *Hex, $i, *hextab, $decoded, $len, $c, $c1, $c2, $code) = @_;
    @Hex = split(' ', '0 1 2 3 4 5 6 7 8 9 a b c d e f', 9999);
    for ($i = 0; $i < 16; $i++) {
	$hextab{$Hex[$i + 1]} = $i;

	# urldecode function from Heiner Steven
	# http://www.shelldorado.com/scripts/cmds/urldecode

	# decode %xx to ASCII char 
	;
    }
    $decoded = '';
    $i = 1;
    $len = length($text);

    while ($i <= $len) {	#???
	$c = substr($text, $i, 1);
	if ($c eq '%') {
	    if ($i + 2 <= $len) {
		$c1 = &tolower(substr($text, $i + 1, 1));
		$c2 = &tolower(substr($text, $i + 2, 1));
		if ($hextab{$c1} ne '' || $hextab{$c2} ne '') {
		    if (($c1 >= 2 && ($c1 != 7 && $c2 ne 'F')) ||

		      ($c1 == 0 && $c2 =~ '[9acd]')) {
			$code = 0 + $hextab{$c1} * 16 + $hextab{$c2} + 0;
			$c = sprintf('%c', $code);
		    }
		    else {
			$c = ' ';
		    }
		    $i = $i + 2;
		}
	    }
	}
	elsif ($c eq '+') {
	    # special handling: "+" means " "
	    $c = ' ';
	}
	$decoded = $decoded . $c;
	++$i;
    }
    # change linebreaks to \n
    $decoded =~ s/\r\n/\n/g;
    # remove last linebreak
    $decoded =~ s/[\n\r]*$//;
    $decoded;
}

sub Getline3 {
    &Pick('',@_);
    local($_);
    if ($getline_ok = (($_ = <$fh>) ne '')) {
	;
    }
    $_;
}

sub Pick {
    local($mode,$name,$pipe) = @_;
    $fh = $name;
    open($name,$mode.$name.$pipe) unless $opened{$name}++;
}
