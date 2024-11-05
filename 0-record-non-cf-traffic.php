<?php

/*
Plugin Name: Record and block traffic that is bypassing your Cloudflare
Plugin URI: https://wpspeeddoctor.com/plugins/
Description: Detect traffic that is bypassing Cloudflare, store IP and URI in /wp-content/non-cf-traffic.log
Version: 1.0.0
Last Updated: 2024-11-05
Author: WP Speed Doctor
Author URI: https://wpspeeddoctor.com/
License: GPL2
*/

$whitelisted_ips = [

	$_SERVER['SERVER_ADDR']??'',
	'127.0.0.1',

];

switch(true){

	case empty($_SERVER['REQUEST_URI']):
	case empty($_SERVER['REMOTE_ADDR']):
	case empty($_SERVER['SERVER_ADDR']):
	case in_array( $_SERVER['REMOTE_ADDR'], $whitelisted_ips  ):
		
		break;

	case empty( $_SERVER['HTTP_CF_RAY'] );

		file_put_contents( WP_CONTENT_DIR.'/non-cf-traffic.log' ,"{$_SERVER['REMOTE_ADDR']} -> {$_SERVER['REQUEST_URI']}\n", FILE_APPEND);
		
		http_response_code(403);
		
		die('Forbidden');
		
		break;
		
}
	
unset( $whitelisted_ips );




