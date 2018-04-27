<?php
class secure_config {

    public static $protection_modules = array(
        "disallow_bots"=>true,
        "logging"=>true,
        "domain_check"=>true,
        "flood_protection"=>true,
        "header_protection"=>true,
        "ssl_protection"=>true,
        "ip_block"=>true,
        "xss_attack"=>true,
        "sql_injection"=>true,
        "login_check"=>true,
        "login_brute"=>true,
        "google_analyitcs"=>false,
        "sql_safe"=>false
    );

    public static $site_dir = "site";

    // NOT WORKING
    public static $google_analyitcs_id = "UA-99096239-1";
    // NOT WORKING

    public static $ssl_mode = array("Strict"=>true,"Flexable"=>false,"Off"=>false);

    public static $allowed_domains = array(
        "{YOUR DOMAIN}"
    );

    public static $sql_login = array("hostname"=>"127.0.0.1","username"=>"root","password"=>"","database"=>"");

}
/*

Stelch Secure
Updated: 7/05/2017
Version: 1.6.1

*/
/* DO NOT EDIT BELOW THIS LINE */
enable();
header("Server: Stelch Secure",TRUE);
function enable() {
    secure::start();
    if(in_array("logging",secure_config::$protection_modules)&&secure_config::$protection_modules['logging']==true){logger::start();}
    if(in_array("login_check",secure_config::$protection_modules)&&secure_config::$protection_modules['login_check']==true){login::start();}
    if(in_array("ip_block",secure_config::$protection_modules)&&secure_config::$protection_modules['ip_block']==true){ip_block::start();}
    if(in_array("ssl_protection",secure_config::$protection_modules)&&secure_config::$protection_modules['ssl_protection']==true){ssl::start();}
    if(in_array("google_analyitcs",secure_config::$protection_modules)&&secure_config::$protection_modules['google_analyitcs']==true){analyitcs::start();}
    if(in_array("sql_safe",secure_config::$protection_modules)&&secure_config::$protection_modules['sql_safe']==true){sql::start();}
    if(in_array("domain_check",secure_config::$protection_modules)&&secure_config::$protection_modules['domain_check']==true){domain_check::start();}
}
class ssl {
    /* MODES: 1=Strict 2=Flexable 3=Off */
    public static $mode = 0;
    function start(){
        if(in_array("Strict",secure_config::$ssl_mode)&&in_array("Flexable",secure_config::$ssl_mode)&&in_array("Off",secure_config::$ssl_mode)){
            foreach(secure_config::$ssl_mode as $ssl_mode => $value){if($value==true){if(strtolower($ssl_mode)=="strict"){$mode=1;}else if(strtolower($ssl_mode)=="flexable"){$mode=2;}else if(strtolower($ssl_mode=="off")){$mode=3;}else{$mode=3;}}}
        }
    }
}
class secure {
    public static $deny = false;
    public static $deny_type = 0;
    function start(){secure::validate();}
    function validate(){
        if(in_array("flood_protection",secure_config::$protection_modules)&&secure_config::$protection_modules['flood_protection']==true){$contents = file("/var/www/requests_raw.txt");$req_count=0;foreach($contents as $line){$args=explode(">",$line);if($args[1]==$_SERVER['REMOTE_ADDR']&&(((int)$args[0])-(time()))<10){$req_count=$req_count+1;}}if($req_count>10){secure::$deny=true;secure::$deny_type=4;}}
        if(in_array("xss_attack",secure_config::$protection_modules)&&secure_config::$protection_modules['xss_attack']==true){foreach($_GET as $query => $argument){foreach(secure::$html_tags as $tag){if(strpos(strtolower($argument), $tag)!==false){secure::$deny=true;secure::$deny_type=1;}}}}
        if(in_array("sql_injection",secure_config::$protection_modules)&&secure_config::$protection_modules['sql_injection']==true){foreach($_GET as $query => $argument){foreach(secure::$sql_inject_tags as $tag){if(strpos(strtolower($argument), $tag)!==false){secure::$deny=true;secure::$deny_type=2;}}}}
        if(in_array("header_protection",secure_config::$protection_modules)&&secure_config::$protection_modules['header_protection']==true){if(strlen($_SERVER['HTTP_USER_AGENT']) < 5){secure::$deny=true;secure::$deny_type=3;}}

        secure::execute();
    }

    function execute() {
        if(secure::$deny==true){if(secure::$deny_type==1){echo error_pages::$xss_prohibited;logger::write("XSS");}else if(secure::$deny_type==2){echo error_pages::$sql_prohibited;logger::write("SQL_INJECTION");}else if(secure::$deny_type==3){echo error_pages::$ddos_bot;logger::write("INVALID_BROWSER");}else if(secure::$deny_type==4){echo error_pages::$ddos_bot;logger::write("DOS_BAN");}exit();}
    }

    public static $html_tags = array("\\","<!-","-->","</script","<script","<?","?>","<b","b>","/b>","b/>","<font","font/>","/font>","<meta","/meta>","meta/>","<track","/track>","track/>","<doctype","<!doctype","<a","/a>","a/>","<abbr","abbr/>","/abbr>","<address","address/>","/address>","<applet","/applet>","applet/>","<area","/area>","area/>","<article","article/>","/article>","<aside","/aside>","aside/>","<audio","audio/>","/audio>","<base","/base>","base/>","/basefont>","basefont/>","<bdi","/bdi>","bdi/>","big/>","/big>","<big","<blockquote","<body","/body>","body/>","<br","<button","<canvas","<center","<cite","<code","<col","<colgroup","<datalist","<dd","<del","<details","<cfn","<dialog","<dir","<div","dl","<dt","<em","<embed","<feildset","<figcaption","<figure","<footer","<frameset","<h1","<h2","<h3","<h4","<h5","<h6","<head","<header","<hr","<html","<i","<iframe","<img","<ins","<kbd","<keygen","<label","<legend","<li","<link","<main","<map","<mark","<menu","<menuitem","<meta","<meter","<nav","<noscript","<object","<ol","<optgroup","<option","<output","<p","<pram","<param","<pre","<progress");
    public static $sql_inject_tags = array('"');
}
class domain_check {
    function start() {
        if(domain_check::checkDomain()!=1){echo error_pages::$domain_prohibited;logger::write("DOMAIN_DENIED");exec("iptables -A INPUT -s ".$_SERVER['REMOTE_ADDR']." -j DROP");exit;}
    }
    function checkDomain(){
        $result = 1;
        if(!(in_array(strtolower($_SERVER['SERVER_NAME']),secure_config::$allowed_domains))){$result=0;}
        return $result;
    }
}
class login {
    function start() {

    }
    function check() {

    }
}
class logger {
    function start() {logger::file_check();}
    function file_check(){
        date_default_timezone_set('America/Los_Angeles');
        $format = '%d/%m/%Y %H:%M:%S';
        $strf = strftime($format);
        if(file_exists("secure.log")){
            $log = file_get_contents("secure.log");
            $log_file = fopen("secure.log", "w");
            $log .= "\n";
            $log .= $strf." || CLIENT CONNECTED\n";
            $log .= $strf." || IP: ".$_SERVER['REMOTE_ADDR']."\n";
            $log .= $strf." || SITE: ".$_SERVER['SERVER_NAME']."\n";
            $log .= $strf." || SERVER: ".$_SERVER['SERVER_PROTOCOL']."\n";
            $log .= $strf." || METHOD: ".$_SERVER['REQUEST_METHOD']."\n";
            $log .= $strf." || BOT: ".(bot_block::check()?'true':'false')."\n";
            if(isset($_SERVER['QUERY_STRING'])&&$_SERVER['QUERY_STRING']!=""){$log .= $strf." || QUERY: ".$_SERVER['QUERY_STRING']."\n";}
            if(isset($_SERVER['HTTP_REFERER'])){$log .= $strf." || REFERER: ".$_SERVER['HTTP_REFERER']."\n";}
            $log .= $strf." || BROWSER: ".$_SERVER['HTTP_USER_AGENT']."\n";
            fwrite($log_file, $log);

        }else {
            $log_file = fopen("secure.log", "w");
            $log = "";
            $log  = $strf." || CLIENT CONNECTED\n";
            $log .= $strf." || IP: ".$_SERVER['REMOTE_ADDR']."\n";
            $log .= $strf." || SITE: ".$_SERVER['SERVER_NAME']."\n";
            $log .= $strf." || SERVER: ".$_SERVER['SERVER_PROTOCOL']."\n";
            $log .= $strf." || METHOD: ".$_SERVER['REQUEST_METHOD']."\n";
            $log .= $strf." || BOT: ".(bot_block::check()?'true':'false')."\n";
            if(isset($_SERVER['QUERY_STRING'])&&$_SERVER['QUERY_STRING']!=""){$log .= $strf." || QUERY: ".$_SERVER['QUERY_STRING']."\n";}
            if(isset($_SERVER['HTTP_REFERER'])){$log .= $strf." || REFERER: ".$_SERVER['HTTP_REFERER']."\n";}
            $log .= $strf." || BROWSER: ".$_SERVER['HTTP_USER_AGENT']."\n";
            fwrite($log_file, $log);

        }
    }
    function write($type){
        $log = file_get_contents("secure.log");
        $log .= "\n";
        $log .= time()." || ACCESS DENIAL\n";
        $log .= time()." || IP: ".$_SERVER['REMOTE_ADDR']."\n";
        $log .= time()." || BROWSER INFORMATION:\n";
        $log .= time()."    || BOT: ".(bot_block::check()?'true':'false')."\n";

        $log .= time()." || TYPE: ".$type."\n";
        if(isset($_SERVER['QUERY_STRING'])&&$_SERVER['QUERY_STRING']!=""){$log .= time()." || QUERY: ".$_SERVER['QUERY_STRING']."\n";}
        file_put_contents("secure.log",$log);
    }
}
class ip_block {
    function start() {
        $ip_block_reply = ip_block::test_connection();
        if($ip_block_reply==3){echo error_pages::$ip_denied;exit;logger::write("IP_BLACKLISTED");}
        if($ip_block_reply==1){echo error_pages::$proxy_prohibited;logger::write("VPN/PROXY");exec("iptables -A INPUT -s ".$_SERVER['REMOTE_ADDR']." -j DROP");exit;}
    }
    function test_connection() {
        $contents = file("/var/www/blacklist_ip.txt");
        $result = 0;
        foreach($contents as $line) {if($line==$_SERVER['REMOTE_ADDR']){$result=3;}}
        return $result;
    }
}
class sql {
    public static $conn = null;
    function start(){sql::connect($sql_login['hostname'],$sql_login['username'],$sql_login['password'],$sql_login['database']);}
    function connect($hostname, $username, $password, $database){sql::$conn=mysqli_connect($hostname,$username,$password,$database);}
    function set_database($database){return mysqli_select_db($conn,$database);}
    function query($query){return mysqli_query($conn,$query);}
}

class analyitcs {
    public static $analyitcs_id = "UA-99096239-1";
    function start(){analyitcs::script();}
    function script(){echo "<script>(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)})(window,document,'script','https://www.google-analytics.com/analytics.js','ga');ga('create', '".analyitcs::$analyitcs_id."', 'auto');ga('send', 'pageview');</script>";}
}

class bot_block {
    function start(){
        if(bot_block::check()==true){echo error_pages::$bot_denied;exit;logger::write("BOT_DETECTED");}
    }
    function check() {
        if (preg_match('/bot|crawl|curl|dataprovider|search|get|spider|find|java|majesticsEO|google|yahoo|teoma|contaxe|yandex|libwww-perl|facebookexternalhit/i', $_SERVER['HTTP_USER_AGENT'])) {
            return true;
        }else{return false;}
    }
}

class error_pages {
    public static $proxy_prohibited = "
		<title>Access Denied</title>
		<style>body{text-align:center;padding:150px;background:#52B3D9;}h1{font-size: 50px;color:#ecf0f1;}body{font:20px Helvetica,sans-serif;color:#bdc3c7;}article{display:block;text-align:left;width:650px;margin:0 auto;color:#EEEEEE;}a{color:#dc8100;text-decoration:none;}a:hover{color:#333;text-decoration: none;}span{color:#DADFE1;}</style>
		<article><h1>IP Denied</h1><div><p>Your IP seems to be on a blacklist.<br />You may not use a VPN on this site.</p><p>&mdash; <span>Stelch</span></p></div></article>
	";
    public static $xss_prohibited = "
			<title>Access Denied</title>
			<style>body{text-align:center;padding:150px;background:#52B3D9;}h1{font-size: 50px;color:#ecf0f1;}body{font:20px Helvetica,sans-serif;color:#bdc3c7;}article{display:block;text-align:left;width:650px;margin:0 auto;color:#EEEEEE;}a{color:#dc8100;text-decoration:none;}a:hover{color:#333;text-decoration: none;}span{color:#DADFE1;}</style>
			<article><h1>XSS Attack Detected</h1><div><p>Your page request has been flagged as dangerous and has been denied.</p><p>&mdash; <span>Stelch</span></p></div></article>
		";
    public static $sql_prohibited = "
			<title>Access Denied</title>
			<style>body{text-align:center;padding:150px;background:#52B3D9;}h1{font-size: 50px;color:#ecf0f1;}body{font:20px Helvetica,sans-serif;color:#bdc3c7;}article{display:block;text-align:left;width:650px;margin:0 auto;color:#EEEEEE;}a{color:#dc8100;text-decoration:none;}a:hover{color:#333;text-decoration: none;}span{color:#DADFE1;}</style>
			<article><h1>SQL Query Detected</h1><div><p>Your page request has been flagged as dangerous and has been denied.</p><p>&mdash; <span>Stelch</span></p></div></article>
		";
    public static $ddos_bot = "
			<title>Access Denied</title>
			<style>body{text-align:center;padding:150px;background:#52B3D9;}h1{font-size: 50px;color:#ecf0f1;}body{font:20px Helvetica,sans-serif;color:#bdc3c7;}article{display:block;text-align:left;width:650px;margin:0 auto;color:#EEEEEE;}a{color:#dc8100;text-decoration:none;}a:hover{color:#333;text-decoration: none;}span{color:#DADFE1;}</style>
			<article><h1>DDOS Attack Detected</h1><div><p>Your page request has been flagged as dangerous and has been denied.</p><p>&mdash; <span>Stelch</span></p></div></article>
		";
    public static $domain_prohibited = "
			<title>Access Denied</title>
			<style>body{text-align:center;padding:150px;background:#52B3D9;}h1{font-size: 50px;color:#ecf0f1;}body{font:20px Helvetica,sans-serif;color:#bdc3c7;}article{display:block;text-align:left;width:650px;margin:0 auto;color:#EEEEEE;}a{color:#dc8100;text-decoration:none;}a:hover{color:#333;text-decoration: none;}span{color:#DADFE1;}</style>
			<article><h1>Domain not Allowed</h1><div><p>It seems that you are using a domain that is not permitted by this site.</p><p>&mdash; <span>Stelch</span></p></div></article>
		";
    public static $ip_denied = "	
			<title>Access Denied</title>
			<style>body{text-align:center;padding:150px;background:#52B3D9;}h1{font-size: 50px;color:#ecf0f1;}body{font:20px Helvetica,sans-serif;color:#bdc3c7;}article{display:block;text-align:left;width:650px;margin:0 auto;color:#EEEEEE;}a{color:#dc8100;text-decoration:none;}a:hover{color:#333;text-decoration: none;}span{color:#DADFE1;}</style>
			<article><h1>IP Prohibited</h1><div><p>The IP address you are trying to view this page on has been Prohibited.</p><p>&mdash; <span>Stelch</span></p></div></article>

		";
    public static $bot_denied = "	
			<title>Access Denied</title>
			<style>body{text-align:center;padding:150px;background:#52B3D9;}h1{font-size: 50px;color:#ecf0f1;}body{font:20px Helvetica,sans-serif;color:#bdc3c7;}article{display:block;text-align:left;width:650px;margin:0 auto;color:#EEEEEE;}a{color:#dc8100;text-decoration:none;}a:hover{color:#333;text-decoration: none;}span{color:#DADFE1;}</style>
			<article><h1>Crawler Detected</h1><div><p>This site's filters have specified that bots/crawlers are to be denied.</p><p>&mdash; <span>Stelch</span></p></div></article>

		";
}
?>