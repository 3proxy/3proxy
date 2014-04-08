#!/usr/bin/awk -f 
BEGIN { 
  scriptname = ENVIRON["SCRIPT_NAME"]
  #for win32
  isql=".\\isqlodbc.exe sqlite " 

  #for unix
  #isql="./isqlodbc sqlite " 


  print "Content-Type: text/html; charset=koi8-r \n\n"
  print "<HTML>\n<BODY>\n";

  # query parse
  query_str = ENVIRON["QUERY_STRING"]
  n = split(query_str, querys, "&")
  for (i=1; i<=n; i++) 
   {
    split(querys[i], data, "=")
    qr[data[1]] = data[2]
   }

  printf "<FORM METHOD=PUT action=\"" scriptname "?rep=1\">"
  printf "datefrom:<INPUT name=\"datefrom\" value=\"2004-06-01\"> "
  printf "dateto:<INPUT name=\"dateto\" value=\"2004-07-30\"> <br>"
  printf "<INPUT type=\"radio\" name=\"userid\" value=\"username\" checked> LOGIN user <br>"
  printf "<INPUT type=\"radio\" name=\"userid\" value=\"userip\"> IP user  <br>"
  printf "<INPUT type=\"hidden\" name=\"rep\" value=\"user\">"  
  printf "<INPUT type=\"submit\" value=\"Report\">"
  printf "</FORM>"
 
   
  #printf "query_str=%s\n<br>",query_str
  #print  qr["rep"]

  if(qr["rep"]=="user")
   {
    cmd = isql " \"select " qr["userid"] ",sum(bytein),sum(byteout),sum(bytein+byteout) from log \
        where ldate > '" qr["datefrom"] "'  AND ldate < '" qr["dateto"] \
        "' group by " qr["userid"] " order by sum(bytein+byteout) desc;\""
    printf " <table WIDTH=100%%  BORDER=1><tr><td><b>user</b></td> <td><b>bytein</b></td> <td><b>byteout</b> </td> <td> <b>bytesum</b></td></tr>"
    while( (cmd|getline result)>0)
     { 
      split(result, rt, "|")
      printf "<tr> <td><a href=\"%s?rep=host&datefrom=%s&dateto=%s&userid=%s&selectid=%s\"> %s <\/a></td><td>%d</td><td>%d</td><td>%d</td></tr>",
      scriptname,qr["datefrom"],qr["dateto"],qr["userid"],rt[1],rt[1],rt[2],rt[3],rt[4]
      totalbytein=totalbytein+rt[2];
      totalbyteout=totalbyteout+rt[3];
      totalbytesum=totalbytesum+rt[4];
     } 
    printf "<tr> <td><br>Total users</td> <td><br>%d</td> <td><br>%d</td> \
    <td><br>%d</td></tr> </table> ",totalbytein,totalbyteout, totalbytesum
    close(cmd)
   }


  if(qr["rep"]=="host")
   {
    cmd = isql "\"select sum(bytein+byteout), sum(bytein), sum(byteout),host from log \
        where ldate > '" qr["datefrom"] "' AND ldate < '"qr["dateto"] \
        "' AND " qr["userid"] " = '" qr["selectid"] \
        "' group by host order by sum(bytein+byteout) desc;\"" 

    printf "<center><b>Detail statistic for user: %s</b></center>",qr["selectid"]
    printf " <table WIDTH=100%%  BORDER=1> <tr><td><b>sum byte</b></td> <td><b>bytein</b></td> <td><b>byteout</b></td><td><b>host</b></td></tr>"
    while( (cmd|getline result)>0)
     { 
      split(result, rt, "|")
      printf "<tr><td>%d</td><td>%d</td><td>%d</td><td>%s</td></tr>",rt[1],rt[2],rt[3],rt[4] 
      totalbytein=totalbytein+rt[1];
      totalbyteout=totalbyteout+rt[2];
      totalbytesum=totalbytesum+rt[3];

     }
    printf "<tr> <td><br>%d</td> <td><br>%d</td> \
    <td><br>%d</td><td><br>Total host</td></tr> </table> ",totalbytein,totalbyteout, totalbytesum
    printf " </table> "
    close(cmd)
    
   }

  printf " </BODY> </HTML>";
} # end BEGIN 


# decode urlencoded string
function decode(text,   hex, i, hextab, decoded, len, c, c1, c2, code) {
    
    split("0 1 2 3 4 5 6 7 8 9 a b c d e f", hex, " ")
    for (i=0; i<16; i++) hextab[hex[i+1]] = i

    # urldecode function from Heiner Steven
    # http://www.shelldorado.com/scripts/cmds/urldecode

    # decode %xx to ASCII char 
    decoded = ""
    i = 1
    len = length(text)
    
    while ( i <= len ) {
        c = substr (text, i, 1)
        if ( c == "%" ) 
             {
           if ( i+2 <= len ) 
                {
              c1 = tolower(substr(text, i+1, 1))
          c2 = tolower(substr(text, i+2, 1))
          if ( hextab [c1] != "" || hextab [c2] != "" ) {
          if ( (c1 >= 2 && (c1 != 7 && c2 != "F")) || (c1 == 0 && c2 ~ "[9acd]") )
                   {
             code = 0 + hextab [c1] * 16 + hextab [c2] + 0
             c = sprintf ("%c", code)
           } 
                  else { c = " " }
          i = i + 2
        }
         }
        } else if ( c == "+" ) {    # special handling: "+" means " "
            c = " "
        }
        decoded = decoded c
        ++i
    }
    # change linebreaks to \n
    gsub(/\r\n/, "\n", decoded)
    # remove last linebreak
    sub(/[\n\r]*$/,"",decoded)
    return decoded
}
