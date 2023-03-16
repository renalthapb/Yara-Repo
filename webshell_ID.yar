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

rule htaccess_rewriter {
   meta:
      description = "htaccess_rewriter"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-01"
      hash1 = "7d232f31c931c7f7b41339775539dc4014f2a81770c9d0c3a0a144b2c094940f"
   strings:
      $x1 = "<?php error_reporting(0); @ini_set('error_log', NULL); @ini_set('log_errors', 0);  @ini_set('display_errors', 0);  echo \"FoxAut" ascii
      $s2 = "W5kZXgucGhwIFtMXQo8L0lmTW9kdWxlPgojIEVORAo=\"); if (file_exists(\"$root/wp-config.php\") && file_exists(\"$root/.htaccess\")){ u" ascii
      $s3 = "open(\"$root/.htaccess\",\"w\"),$htaccess);} }elseif (file_exists(\"$root/configuration.php\") && file_exists(\"$root/.htaccess" ascii
      $s4 = "75%73%66%6F%78%2E%63%6F%6D'))</script> , anonymousfox.net<br>Telegram: @Anonymous_Fox\\n\"; if (isset($_GET[\"403\"])){ $htacces" ascii
      $s5 = "e(fopen(\"$root/.htaccess\",\"w\"),$htaccess); } } if (file_exists(\"$root/.user.ini\")){ unlink(\"$root/.user.ini\"); }  } $cod" ascii
      $s6 = "URNTRANSFER, TRUE); curl_setopt($curl, CURLOPT_URL, $url); curl_setopt($curl, CURLOPT_USERAGENT, \"Mozilla/5.0 (Windows NT 10.0;" ascii
      $s7 = "ink(\"$root/.htaccess\"); if (function_exists('file_put_contents')) { file_put_contents(\"$root/.htaccess\",$htaccess); }else{ f" ascii
      $s8 = "(\"$root/.htaccess\"); if (function_exists('file_put_contents')) { file_put_contents(\"$root/.htaccess\",$htaccess); }else{ fwri" ascii
      $s9 = "<?php error_reporting(0); @ini_set('error_log', NULL); @ini_set('log_errors', 0);  @ini_set('display_errors', 0);  echo \"FoxAut" ascii
      $s10 = "p://'.$_GET[\"php\"]; $t = \"<token>000000000</token>\"; if (empty($code) or !stristr($code, \"http\")){ exit; } else { $php=fil" ascii
      $s11 = " curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0); curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0); } curl_setopt($curl, CURLOPT_HEAD" ascii
      $s12 = "ER, false); return curl_exec ($curl); } ?>" fullword ascii
      $s13 = "V5 [The best tool]<br>Download: anonymousfox.co , <script type='text/javascript'>document.write(unescape('%61%6E%6F%6E%79%6D%6F%" ascii
      $s14 = "HAkIC0gW0xdClJld3JpdGVDb25kICV7UkVRVUVTVF9GSUxFTkFNRX0gIS1mClJld3JpdGVDb25kICV7UkVRVUVTVF9GSUxFTkFNRX0gIS1kClJld3JpdGVSdWxlIC4ga" ascii
      $s15 = "contents($code); if (empty($php)){ $php = curl($code); } $php=str_replace(\"<?php\", \"\", $php); $php=str_replace(\"?>\", \"\"," ascii
      $s16 = "WOW64; rv:43.0) Gecko/20100101 Firefox/43.0\"); curl_setopt($curl, CURLOPT_FOLLOWLOCATION, TRUE); if (stristr($url,\"https://\")" ascii
      $s17 = "base64_decode(\"IyBCRUdJTgo8SWZNb2R1bGUgbW9kX3Jld3JpdGUuYz4KUmV3cml0ZUVuZ2luZSBPbgpSZXdyaXRlQmFzZSAvClJld3JpdGVSdWxlIF5pbmRleC5w" ascii
      $s18 = "eval($php); } function curl($url) { $curl = curl_init(); curl_setopt($curl, CURLOPT_TIMEOUT, 40); curl_setopt($curl, CURLOPT_RET" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 6KB and
      1 of ($x*) and 4 of them
}

rule shell_kids_jaman_now {
   meta:
      description = "shell - Kids Kids Jaman Now"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-01"
      hash1 = "e3a8aa44722f2e6b12d003bede1ad8a5bbb649f105a3d24ae5a9a2849f089c7a"
   strings:
      $s1 = "//Shell Recoded From IndoXploit Shell" fullword ascii
      $s2 = "$Kidsjamannow= \"7X35e9rIsujPme+b/6Gj8Q32jc1zO4nXGeyAaoyxjZdZHp9RJG6MhSRAU8zk/e2vqhepJQQGh9xmzn2Ts0v0RV3dXV1IXV1deriG4XZ33TAt3Vx" ascii
      $s3 = "2H25oDwviqLEMgj/cyB2KV4xvSPyUfXvcRZHkYuafb350kuKZf+C0aR7s218WYOmw+woYVZaQ09bY9BN+YenbYjzogJlmTIJ0bChoNVoAWf8SZ0WDcyhjgEI/D66HiBQ" ascii
      $s4 = "T9qLUibmfw8lQWfMRW/MRcGYwZBEdtkFru+3gZwOO1rVeYKWdDdoAzTOLWxZSgL9BpK2AkipBW2qyxr+zXP0CVlys6+BwvpKRf0GdaY+1qCS0+hbwB42RE7C/+Xw/37r" ascii
      $s5 = "//Thanks Buat Yg Udh Support Buat Shell Ini" fullword ascii
      $s6 = "2lbBp+2i5ZTuq2pFq+w37Fx6+juXIvTceCfFQKYoOIB5OslVZnEqWh23vqhkkFqBNPtQFLov5xo/GyHU9+06Hatd+MIBIn+hAosjBOqlxQzOqd8hdFRu+3OYLA+GNrsF" ascii
      $s7 = "+xflg3eAaKltEPgYY8d2thKXxdRQd7g+yfFotUuFLk8qYBi2xt0WglhdsAsO1gB5aVBaNChtX8Jl7I5eJB+5H+tj7O4Wq0sKbTyq/bq6runLpHRoPMNvw4XanlK4uq+2" ascii
      $s8 = "OryrnH8u+hs3BwP6fWOQLdwB4zk8HBydH5RNvRvO4CQGoNUGVHp1o73nlQe1IyBzj8LGCwnNs+MCMDDBuHV92r8p6kYmBGgPi0h/Dx8o2/fOKD7AfEw/h2dkd7g4D2WI" ascii
      $s9 = "s1hCOXTmzCmDOhkj8aaWRld3Kp4cuNEnSRvLj0aSrXy02ktenBJutBKqBcxnrKlU8WCiWc+0/lpZPGQDi+fUAwxfx3Ljqu0XZ8m3zDqoznWTnVfFculsmV3rfkPzp7NI" ascii
      $s10 = "ohteZSk2vDMD1J1Td/dppWuxQihYnh0jmEQgNRU2YIBJ+IMcpfMzA3vSR7ef2j2DPyvXeU4UNNPrba4+hxXRedCT3N1Q+mpz5Cx06KkoKsrscHMAruNEJy4E0TQ1RYXf" ascii
      $s11 = "/1GT/1compT2PRFxEsQgNZqcVwCQlLaZABPjGqdDx6TjsjT6nyW+rUygbZz8iMkywqL1S4mmV9+BoeXwxSW2GxI8ikhU7uSrgyBNOnyjCipecoCfImE6y4lpX+HhzRDC" ascii
      $s12 = "lGDffWP9HeZuNAclOKCC+IGtUTmpzBSCioaMDid0Ka4Tyxx1oo6boHz/ZjJY/45KwumfKTxPMXK7n9stN1qNRxFWvL5WGNl5dCCHlhjjN21EK/KiE31TUD9Efoc29PQJ" ascii
      $s13 = "BP0Mc1QFqtdbDRnOAZ414mHE2dddcGlPoCAdhBnAIBT6K2yb02SAg6RpL87JBXy8c9Hjbc8HK38MTlogAnfrBQkf+tmkktsaaz7wqFv4f2U/sacTIPpNQniaO6hPI8/E" ascii
      $s14 = "hdJytbhZZUbVuty7u9s7vturlA93e4Vyd0Odqm+pZ0o/qhZ4l6f7SHmueAErm7EmGmVwNReEyYSPAUoFUwfB9jXDjeaIAecgBAUDbqE6M7Rtnl3/1tRZ16j3GvYiSoyD" ascii
      $s15 = "v196lT+X7+7L9N9+JpNMYtvl+497p/Cpwu+nh8yeut9d3YDfmUk58Z+SSejfyvX6bLkKH73yHcvBShfhX7FLvfdivn3Mrn11Nz6cPxreaPXovE2+Pa0c7usXjY/X/lbR" ascii
      $s16 = "YeJlm0NCIhiihBQzb9ybCsxYU7OpgIyhPlw+UqEqVFXww3VKAyL8IMliUElgBkTS6hiykm+FfuuxHdxinKx+8wzcwWiMpchGO7Sj4mKohiY8ddPhYjaQodtjjWc6fpD1" ascii
      $s17 = "i3LDCFvvuTMVNlhmgyAngCDSyTYb690W1fvSvsbMvjspZ1Dcwcu174AmatCy4el25R078laPYJJJRVvbGQ4s6Tkx0V7Mvbrh6lDPMPAQyGRIz2j4Cos8vsbjTwEIdneT" ascii
      $s18 = "PLhc+ZSC5ojXXXzrDhtze2ShXqoWj6rFL6nrg4P9+iH8qpevqoWD1NelJfIXTADYbbnnqqYBICxdt9qLypWm9Xy3o5nKMkRXfkZi4Md9qWPOkvbb9m7xDr+6lg3ltIH7" ascii
      $s19 = "UUF7C66JPLKrNVxoRMnArwxo/2rwhrfOa1CrQu9/sWcsjP4yi0tmVkV3UjZe3sOLh2J2gagmGLPuRyw1chJnkCZFyxHzQYQZhWrM65bvL6Yyi+n//n1282Qzg/4erDa/" ascii
      $s20 = "bW0j0jdNhPath7Q1tmKsHv07uV+i6BiQIfaEo/+W87N1y5GTLF6S5kSOl1enGWonrFoUjpTLBmUy2T6wWE6gUUcE3EOKVdCnAM4uv42DN0ho1tlRIMmdQdHTv7GjYOHN" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 90KB and
      8 of them
}

rule shell_ipt {
   meta:
      description = "shell - IPT"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-01"
      hash1 = "7b730ab8ac42b5dfa4d4e65dd06f8d5e4dde63665bec3a76eb2e9fb0336f569c"
   strings:
      $s1 = "<style type=\"text/css\">@import url(\"https://fonts.googleapis.com/css?family=Fredericka+the+Great|Kaushan+Script|Press+Start+2" ascii
      $s2 = "<style type=\"text/css\">@import url(\"https://fonts.googleapis.com/css?family=Fredericka+the+Great|Kaushan+Script|Press+Start+2" ascii
      $s3 = "/*------------------ Login Data End ----------*/" fullword ascii
      $s4 = "/*------------------ LOGIN -------------------*/" fullword ascii
      $s5 = "<link href=\"https://fonts.googleapis.com/css?family=Lacquer|&display=swap\" rel=\"stylesheet\">" fullword ascii
      $s6 = "if(!empty($_SERVER['HTTP_USER_AGENT']))" fullword ascii
      $s7 = "        if($_POST[\"usrname\"]==$username && $_POST[\"passwrd\"]==$password)" fullword ascii
      $s8 = "    #loginbox { font-size:11px; color:green; width:1200px; height:200px; border:1px solid #4C83AF; background-color:#111111; bor" ascii
      $s9 = "$email=\"wawankepaladesa@gmail.com\";" fullword ascii
      $s10 = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
      $s11 = "echo('<pre>'.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</pre>');" fullword ascii
      $s12 = " transparent;content: '';height: 0;left: 50%;margin-left: -10px;position: absolute;top: 40px;width: 0;}" fullword ascii
      $s13 = "                print'<script>alert(\"UserName/PassWord Salah Gan\");</script>';" fullword ascii
      $s14 = "Permission : <input name=\"perm\" type=\"text\" size=\"4\" value=\"'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'\" />" ascii
      $s15 = "            print'<script>document.cookie=\"user='.$_POST[\"usrname\"].';\";document.cookie=\"pass='.md5($_POST[\"passwrd\"]).';" ascii
      $s16 = "            print'<script>document.cookie=\"user='.$_POST[\"usrname\"].';\";document.cookie=\"pass='.md5($_POST[\"passwrd\"]).';" ascii
      $s17 = "$password=\"W4NT3K\";" fullword ascii
      $s18 = "ame=\"passwrd\" value=\"password\" onfocus=\"if (this.value == \\'password\\') this.value = \\'\\';\"></td></tr>" fullword ascii
      $s19 = " if(get_magic_quotes_gpc()){ foreach($_POST as $key=>$value){ $_POST[$key] = stripslashes($value);" fullword ascii
      $s20 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      8 of them
}

rule shell_unidenttified {
   meta:
      description = "shell - unidenttified"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-14"
      hash1 = "5d17dd31dbb1b38b5622222f84dee6fef8cf0db17ab7ab9587f891bdc4e00556"
   strings:
      $x1 = "$VwGQECVgMV='func'.'t'.'ion'.'_'.'e'.'xi'.'s'.'ts';$wJKCM='eva'.'l';$YvVLkbUAdSRd='g'.'zin'.'f'.'la'.'t'.'e'.'';$YqtmwUJzgzQX='A" ascii
      $s2 = "pEWd2JwDll3OFZveMSi/J8mxHxxl+Yyclr17+PKfOFrb/pOXxbd+dE3uDE/MmnI8ZrCG6Hwzoaqx2S57C+l+CYkGyrxZPrAwtMpQ5IuM8k/UjRbBNd9n3ybq5SUZFXhQ" ascii
      $s3 = "3K5omLTragKBRFs4vFRE07VWGZOfROrWWQJQeB8KBa640T6rExEcbOQhh30tgJ8JNxqamuXwM8S8qYyA/vy6IzzgKWiW97J8IdH76P2fjFkyDO8jKl1aB8Hw1z30z3hc" ascii
      $s4 = "5ybtb3NA6Qn1u1P7oPkZt0ORF1cDxG8GJiUySQU4T+aRGcRG8xHlfF8AVnaJqPIpedB+6akKxYT3yg5dnHSx7VpwpEALyI5yl3ef0cK5+saGfwJ8CnfP19qwsM7aikVf" ascii
      $s5 = "w+t0gI7Du2qJ56DsB+LFcDdA2DN65OOPJlc7VUUvQ3JjpwNzhJ/76sorE4+8MaYBlmpdLl+ytF7q85e4N4uJ9taYvcM4Emrt0Vmy7jdkPIJizL92GfrfZ6d265RRr1C7" ascii
      $s6 = "zdQZTIQqBvIp6pmPDiV2jhAoYoAVJNluzeGlDCfP1N9rSMIzialzkGqwZBbplKgoSclJSA9he4x9uDOIcHGcIawVc3kdIy1Q34tNBZDxxWYXrP0CSL0qKykOZDfH064r" ascii
      $s7 = "iK7sf4fOvqrO+/TUXUebXe3KVMsrph9b78+F8Hrkjs9emUAJFulTSPylSrtgtPFY43ntWCJa2rrILDMrYl06FGBED6wB9o/LDUJNMGiqwdOSL62IxW5RLfAztJG5AG4s" ascii
      $s8 = "D+mqJIVxaF4iY2KXBBn1uBG34EtltYG3lBPwM54CqOUmLxY18EvS/EEgD0YOY4y/SAqz/7zD7o9ZOf72tzkKdkot6UPqjUO0piy4pl2DubWU1USPykjNcFRonEOWGhYo" ascii
      $s9 = "NV37itu0B3jUUh9+yvo4MV8XmRgjMNwAltS6zblvAUwzLpzetdbxlcG3Z/CiPNgZ5aIs6JD5aizRAUuSt3WGtuyTcdZ+4EHxaEk42tBfMUqi7/uBtEYETBsRjXJi0Weu" ascii
      $s10 = "ip1/woL6Jr7SMez65y16YAktz+VmHkcbkfV696W/4RrXPHecKGeIdLLK6HT/+3f+nCYVGMZDPEupVzOwguk4CvRzRXj9i+5oKv19DnwlB5t13ysUsfGoLQTzMdkhlRWb" ascii
      $s11 = "vNHBy0S865QpfejGDCmcd7D1mLzHBJr9QYJxOLw22qdVZHkn3EkSfVCiH9KBspyTxsHn8X6nxeSf6u3XCEBt6VHO+D4lyDgSUKf7tykxCka5G5+SCgFHWRP2BiF5Hqsm" ascii
      $s12 = "cEGAruj7P2TURoqC1Qom59Ds5WP0Jckrii02N2Bk+hcDJcNT+mf9hKOf1h5rDAirctm/Fl7DqSh5wOpne+LReVMfcUWjdvP1gKoPQwyB16xo6a0XBstLZPn/OMDbFvxW" ascii
      $s13 = "nHTX6/VkB9gfJnBMH2OrJz12UX17OjuALgog2zUVbPSXu70Nv3v22GWCpi50RH2J1o47CofT1je3TjghV+XoKHBjP+doh1kUpdLlQs9CK4rDf68ehNpPmM4tfCs4OBas" ascii
      $s14 = "iTWHMt2L1Nkx+CBfzLh3LoGwddJilh6FRdBSMPXNXZgLJVT4IZpMywPIgC+NJrhy6be/o26RAk0snp3wb+LCfyAc4XTW38afxn5Vg5AbIU+15Gu7XYj4/2eN8CPFt/Iy" ascii
      $s15 = "5GCMrO8ODgmJ+NZF+5zAIbSsPY7i1jmJqoJNMzjkMLAo3pzj/VYVaVQVY73VGIhWbSiOdhZO2yYS28Rcp8yntUxv5dZy5Q9t6kykAmsPq7vJ1t7qepIg3aRxYpsh7fH3" ascii
      $s16 = "O6Zpqxyemiu5blpec+1wH6Gtm2Q3KGtUaOF4jUr58icP9y1ciegVCwLogUx9MuvzNTglB66Hs03rVrVZcJuGx26Uf7egeIMfBM4wiI7BEofcIIp2NiRXjHdThGUHaCmL" ascii
      $s17 = "ASqnyQMYxpRmxKrxlNvSEye0lnyuJnVs9PkDDJHuVbbOfrtfzBlNTE6ANOmbrR4JiGb1K/xADAMBvTrWykUDf6QFZqe0f9gzMaj00XKbabMsgFpowDBbeQ/OloebwQYd" ascii
      $s18 = "q2RlQqH37FuHiRJkn+CCuNDWBWTeqZlx8lUoWOPUX/no9DnM476efxOjs2osvPWduNPQGlZAIrCVNbX+txF6c+lfL+WTBaitesNqPg8HeJNfEX6XzK/GD9PTJCUsfj+d" ascii
      $s19 = "0x6TvlPji/4yZ2Hcbdeye/SxbQOUB/yaHpfO5safHR6G8GtSUbOmgokioCC6RL0Qn4o4UvDgPWcgcYZtbXOkxG6rp3eKBn9Jp0PDVZ6teyPbmjjsKe0uRx0uK0S/RztX" ascii
      $s20 = "OexVyWhr91yTHLlAdbSf/Eknb9KEqwO0wWWlg0pgiAfrzi8D4AYcOGjxO0izyrhRzQYmfkmAfiWqK7W4pIScSsFDLlhsXnsKkXQxCr356yxrMioqpPNumvcJ2mRbbAjd" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule shell_zain_bani {
   meta:
      description = "shell - zani_bani"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-14"
      hash1 = "0e0c060684d89eb04ea7c4a4a07887fbe119ec1ff7574bf085517ad7989b04ef"
   strings:
      $x1 = " goto Fy6Bg; Fy6Bg: error_reporting(0); goto MqCa6; MqCa6: function MhAJ1() { goto a6tUo; a6tUo: $ir7ui = 'I could not have a mo" ascii
      $s2 = "7Ru2Nds01sRcoe+Rrd9tA49eGAV76Mo8XtTPw69SwuY3xVg+tX73uo9NzOQZpIpEox4m/c1M6CVVWsvQlUJ7gLAv0j0rHq7WraboPDj3EqpoRs6auUpTYVW4lvxZzxX0" ascii
      $s3 = "Ve6lDnoRnOVC95+ajutDF8NA+6qxpxEBXPeGUgSABRznBuW/69p5PaYotB5ucDaYuiDLlNn4ul2Z4N3hlda4wUuxcZnEGDDPBd8DicKwEbiV+lf05kj0ZTM9mJhV4DQb" ascii
      $s4 = "MZk+4Uu0lYfK8ckwCvz/YpcoUvaUEMkvpOrCp2DJBAIAizeWV2b+a01ac62QltlT8mACT+CGZYDfxC8/9LjKXRTTxMRpRTwPuctdTkcZO73lQyD87OP0cscnhYPEP7N4" ascii
      $s5 = "lc1ZRag80DOYVQJGvNe4o+bcbMz4VpuzZhLHGbDvFb5vcXhb5Deye0iRMmK76hmMQ5FyZnjwzGKL0giBaAQKKg5zog3EBhyjaGI8509hXUEaRVxv4qHSLWY7+7OTZKcR" ascii
      $s6 = "hnHLae/aP9oTte8fRUuap5ab9cqCI+B87XMuPCqCLPFq/5KsEDRJRPBwiltsiVf6v9rkZe1czi2Sy33XkaktowWkAQBhYBq8oMjhDRXVBHXsZYlOGAOKglm4dDh8Iu7n" ascii
      $s7 = "opLoGX0cPoVUW1M/6M87PLNMytI1Qdnl4tPFPQSwNnhFZ356zDr/z1lMz7PsGWrqN/AfnuQL+2ibSV7UydTI9Qegvh5nPL+2VH+EvAMWFn1n9KHyVTxlHd3xjjC48kRT" ascii
      $s8 = "lTslt3B6C/eC3y4sFUggpbqf9YG7nfQ/0/OlRrAqHZt2NaG5qIdw7IQCQzYIaMjwiRcoRtBLGIM3hF7UusqdVVjfouC91Uge0egu1lwbHB4lCqLMjT/o7oPfP1BxxJe6" ascii
      $s9 = "k/9JKzpvtzXPK4nQ1jGxYzLdfvIOFPCx464jfYYoZV2z2C6HL8iqKFMK3NctOPFCUr5IMS95lHuab8d8aA/Jc5yyfQwH6fmy/V+djUNZhkMfToDaOywypkgr6pKlM0d+" ascii
      $s10 = "SwHgKNMoZoiUXABBzFTyku1mQHYDO62M1RcslJoQMaKOTopbxZkeztlzCwhp+3BfxC5U9R3OSMJFrZxtk8GdFvVZL1RuNrux5GCX0EANBGKyW8H8OAFEcqeuR2pL/4dc" ascii
      $s11 = "fHLr421IG6SRGruNolDOqMGHmNcz6a7Ck7oWySjsapjT6Is33Ezt/4hFa4DTppCkX9PzNq5FcCFKqY7+9LWcL/T6nURrRFICvu9uSEa9Pu1xi3LeA6qbDNav7p9NXhLF" ascii
      $s12 = "kIyX9xh9e59xcSpylsRIOrj9cfnD4Z6vJDkBxafye4DP6k41cJa0Sk7CPNr+l+tge/8IKod6CXRvfhE+VKob2WGoCaitN46BGBfYn4K4eM2RVR3LlkYf52J+oIlqaKuf" ascii
      $s13 = "9KAwEHnPvTXWP/zFfXUfl1twWQ/A3/HcrrQJU5d5pl3hWkzOeqB2lTgCMe2mvCvHrPuse/4dBQCi80hSOciJ40PxBDx07f8AuxrgtEj96rS4jNa9P3OyX/rsKiWYM1dL" ascii
      $s14 = "GenUuE4yvxTrtM3HpbhMBDUt/yj0vahDm15XuTBbJWRtNJzDtlqUBnHzGNvTt2wN7HStfpqBxbZjfpwyOiiwHDzgQEvKzx+pGGoGz0OS8zDWVW66ntbh+K7Q6lRuImas" ascii
      $s15 = "7FY2BWHkui2MGdy/jTZ7gghx0XJvPou/WPZp/c2Rl4xQPv/lC+EisxiqNPiHu2S+U+T//fuy+5TizUOsxiTzzEFBV5RCCK04NurdYPLLwyN3Mrk7owdqMPKlivOTzuQR" ascii
      $s16 = "FAIjbQ3nc7UOeIEp2rp3kzOGA2XrQb5aCCvEiLUCpM76Gk2Hm32qRkBKf+JhuzFVz+Mectpb2FjJ1Ovo5AY1/BlvyG7TWzgeWXs339aHxt2F7fEDI7cXfMqN8QotADxc" ascii
      $s17 = "T464kdY+15D55temkD8aJtq88N8G+H1+6dFK5+bgzis9otXnE3ybt+o3Z3FI5PZZ0512ROs4k8fT2Y1F1t7x1+ADxdou/WVI+exdEdrb+xW60f9YYjmUT9b7ZfGhpGfU" ascii
      $s18 = "6wYZxjxUgu5SxqpjJwDJdg743bCKNt4CtubaIopm3rhpefKtyX4jS3s/1ZzILbERrMnXKIme14e7yGXPXjLTCwScj093zTN41BT2NFvp77Afdjx+CEFVUtr8AABAQBS2" ascii
      $s19 = "PHDq4uKuYItU+8Wl47DD1cD5n+lBBhy3xezf8xamLxPQaSj8Qg1B6L0ARw4UA1lBOYPtlW9BfVjV3mg8GIhA+WtYpYiJeL14pOKEgTjPptv+r5DzGkWGxbkDTaSJhHQA" ascii
      $s20 = "uO92kH+33Mg8rAguwTyB/UWSIQoh10Sd5gumsVdgAk35ngHIgNM0jBJpFh4XI230deHFaJDmToYM6oBHPygc9YCpS4eUGIR3fBVCc6dHMB+QttQC3gVJFx1M1sCXsgfM" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 80KB and
      1 of ($x*) and 4 of them
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

rule _shell_kids {
   meta:
      description = "shell - Kids"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-01"
      hash1 = "da1a2c174fc4efbac4e00e39156c6bbe01255e7d966307cba623d97bfe94316e"
      hash2 = "039f1bd70181f6feac74926693bb9cfa988ca6ca1c5f19ec51262301e2915e97"
   strings:
      $s1 = "$user = @get_current_user();" fullword ascii
      $s2 = "@ini_set('log_errors',0);" fullword ascii
      $s3 = "@ini_set('max_execution_time',0);" fullword ascii
      $s4 = "if(!function_exists('posix_getegid')) {" fullword ascii
      $s5 = "$gid = @getmygid();" fullword ascii
      $s6 = "$uid = @getmyuid();" fullword ascii
      $s7 = "$user = $uid['name'];" fullword ascii
      $s8 = "</form>\";" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "$group = \"?\";" fullword ascii
      $s10 = "$group = $gid['name'];" fullword ascii
      $s11 = "$i .= (($p & 0x0100) ? 'r' : '-');" fullword ascii
      $s12 = "$i .= (($p & 0x0010) ? 'w' : '-');" fullword ascii
      $s13 = "$uid = $uid['uid'];" fullword ascii
      $s14 = "$gid = $gid['gid'];" fullword ascii
      $s15 = "$i .= (($p & 0x0080) ? 'w' : '-');" fullword ascii
      $s16 = "$i .= (($p & 0x0020) ? 'r' : '-');" fullword ascii
      $s17 = "$i .= (($p & 0x0002) ? 'w' : '-');" fullword ascii
      $s18 = "$i .= (($p & 0x0004) ? 'r' : '-');" fullword ascii
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x3c20 ) and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _shell_mailer {
   meta:
      description = "shell - Mailer"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-01"
      hash1 = "79b19bf8217fc1acb855583c6b2b282be0370f38b0e1bd0974793ae60bcf5533"
      hash2 = "e96e0e5fa2edc90e1c6e5130a220059bfff263c6624bebc8416051472a97b3a9"
   strings:
      $s1 = "$headers  = \"MIME-Version: 1.0\\r\\n\";" fullword ascii
      $s2 = "$testa = $_POST['veio'];" fullword ascii
      $s3 = "$from = $_POST['from'];" fullword ascii
      $s4 = "$headers .= \"From: \".$realname.\" <\".$from.\">\\r\\n\";" fullword ascii
      $s5 = "$to = $_POST['emaillist'];" fullword ascii
      $s6 = "$realname = $_POST['realname'];" fullword ascii
      $s7 = "$email = explode(\"\\n\", $to);" fullword ascii
      $s8 = "while($email[$i]) {" fullword ascii
      $s9 = "  <input type=\"hidden\" name=\"veio\" value=\"sim\">" fullword ascii
      $s10 = "$subject = $_POST['subject'];" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "if($testa != \"\") {" fullword ascii
      $s12 = "$message = $_POST['message'];" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "$ok = \"ok\";" fullword ascii
      $s14 = "if($ok == \"ok\")" fullword ascii
      $s15 = "$count--;" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0xbbef or uint16(0) == 0x3f3c ) and filesize < 20KB and ( 8 of them )
      ) or ( all of them )
}

rule _test_1 {
   meta:
      description = "shell - test"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-01"
      hash1 = "7b730ab8ac42b5dfa4d4e65dd06f8d5e4dde63665bec3a76eb2e9fb0336f569c"
      hash2 = "4500f0420505f3d68460e5e478ba430216a16f193e67df13333bfeff89755095"
      hash3 = "039f1bd70181f6feac74926693bb9cfa988ca6ca1c5f19ec51262301e2915e97"
      hash4 = "cc99a727ef8620faf56ce9325eaacd558b5130dbb57d8ed313124166d6d71e15"
   strings:
      $s1 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
      $s2 = "if(isset($_GET['filesrc'])){" fullword ascii
      $s3 = "if(isset($_POST['src'])){" fullword ascii
      $s4 = "if(rmdir($_POST['path'])){" fullword ascii
      $s5 = "if($_POST['type'] == 'dir'){" fullword ascii
      $s6 = "if(isset($_POST['newname'])){" fullword ascii
      $s7 = "if(rename($_POST['path'],$path.'/'.$_POST['newname'])){" fullword ascii
      $s8 = "if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){" fullword ascii
      $s9 = "elseif(!is_readable(\"$path/$dir\")) echo '<font color=\"red\">';" fullword ascii
      $s10 = "elseif(!is_readable(\"$path/$file\")) echo '<font color=\"red\">';" fullword ascii
      $s11 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
      $s12 = "if(is_writable(\"$path/$dir\") || !is_readable(\"$path/$dir\")) echo '</font>';" fullword ascii
      $s13 = "$scandir = scandir($path);" fullword ascii
      $s14 = "foreach($scandir as $dir){" fullword ascii
      $s15 = "if(isset($_FILES['file'])){" fullword ascii
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0xd8ff or uint16(0) == 0x3c20 ) and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _test_2 {
   meta:
      description = "shell - test"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-01"
      hash1 = "7b730ab8ac42b5dfa4d4e65dd06f8d5e4dde63665bec3a76eb2e9fb0336f569c"
      hash2 = "4500f0420505f3d68460e5e478ba430216a16f193e67df13333bfeff89755095"
      hash3 = "cc99a727ef8620faf56ce9325eaacd558b5130dbb57d8ed313124166d6d71e15"
   strings:
      $s1 = "echo '</table><br /><center>'.$_POST['path'].'<br /><br />';" fullword ascii
      $s2 = "}elseif($_POST['opt'] == 'edit'){" fullword ascii
      $s3 = "}elseif($_POST['type'] == 'file'){" fullword ascii
      $s4 = "echo perms(\"$path/$dir\");" fullword ascii
      $s5 = "echo perms(\"$path/$file\");" fullword ascii
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0xd8ff ) and filesize < 100KB and ( all of them )
      ) or ( all of them )
}
