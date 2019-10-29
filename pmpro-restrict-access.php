<?php
/**
 * Plugin Name: PMPro Restrict Access
 */
/**
 * This code handles loading a file from the /protected-directory/ directory.
 * (!) Be sure to change line 44 below to point to your protected directory if something other than /protected/
 * (!) Be sure to change line 64 below to check the levels you need.
 * (!) Add this code to your active theme's functions.php or a custom plugin.
 * (!) You should have a corresponding bit of code in your Apache .htaccess file to redirect files to this script. e.g.
 * ###
 * # BEGIN protected folder lock down
 * <IfModule mod_rewrite.c>
 * RewriteBase /
 * RewriteRule ^protected-directory/(.*)$ /?pmpro_getfile=$1 [L]
 * </IfModule>
 *
 * OR
 *
 * RewriteBase /
 * RewriteRule ^access/(.*\.html)$ /index.php?pmpro_getfile=$1 [L]
 *
 * # END protected folder lock down
 * ###
 */


function use_pmpro_getfile() {
	if ( isset( $_REQUEST['pmpro_getfile'] ) ) {
		global $wpdb;

		// prevent loops when redirecting to .php files
		if ( ! empty( $_REQUEST['noloop'] ) ) {
			status_header( 500 );
			die( 'This file cannot be loaded through the get file script.' );
		}

		$uri = $_REQUEST['pmpro_getfile'];
		if ( $uri[0] == '/' ) {
			$uri = substr( $uri, 1, strlen( $uri ) - 1 );
		}
		/*
		Remove ../-like strings from the URI.
		Actually removes any combination of two or more ., /, and \.
		This will prevent traversal attacks and loading hidden files.
		*/
		$uri = preg_replace( '/[\.\/\\\\]{2,}/', '', $uri );

		// edit to point at your protected directory
		$new_uri = 'access/' . $uri;

		$filename  = ABSPATH . $new_uri;
		$pathParts = pathinfo( $filename );

		// remove params from the end
		if ( strpos( $filename, '?' ) !== false ) {
			$parts    = explode( '?', $filename );
			$filename = $parts[0];
		}

		// add index.html if this is a directory
		if ( is_dir( $filename ) ) {
			$filename .= 'index.html';
		}

		// only checking if the file is pulled from outside the admin
		if ( ! is_admin() ) {
			// non-members don't have access (checks for level 2 or 3)
			if ( ! pmpro_hasMembershipLevel() ) {
				auth_redirect();
				exit;
			}
		}

		// get mimetype
		require_once PMPRO_DIR . '/classes/class.mimetype.php';
		$mimetype      = new pmpro_mimetype();
		$file_mimetype = $mimetype->getType( $filename );

		// in case we want to do something else with the file
		do_action( 'pmpro_getfile_before_readfile', $filename, $file_mimetype );

		// if file is not found, die
		if ( ! file_exists( $filename ) ) {
			status_header( 404 );
			nocache_headers();
			die( 'File not found.' );
		}

		// if blacklistsed file type, redirect to it instead
		$basename = basename( $filename );
		$parts    = explode( '.', $basename );
		$ext      = strtolower( $parts[ count( $parts ) - 1 ] );

		// build blacklist and allow for filtering
		$blacklist = array( 'inc', 'php', 'php3', 'php4', 'php5', 'phps', 'phtml' );
		$blacklist = apply_filters( 'pmpro_getfile_extension_blacklist', $blacklist );

		// check
		if ( in_array( $ext, $blacklist ) ) {
			// add a noloop param to avoid infinite loops
			$uri = add_query_arg( 'noloop', 1, $uri );

			// guess scheme and add host back to uri
			if ( is_ssl() ) {
				$uri = 'https://' . $_SERVER['HTTP_HOST'] . '/' . $uri;
			} else {
				$uri = 'http://' . $_SERVER['HTTP_HOST'] . '/' . $uri;
			}

			wp_redirect( $uri );
			exit;
		}

		require_once PMPRO_DIR . '/classes/class.mimetype.php';

		// okay show the file
		header( 'Content-type: ' . $file_mimetype );
		readfile( $filename );
		exit;
	}
}
add_action( 'init', 'use_pmpro_getfile' );

/**
 * Redirect user after successful login.
 *
 * @param string $redirect_to URL to redirect to.
 * @param string $request URL the user is coming from.
 * @param object $user Logged user's data.
 * @return string
 */
function a_login_auth_redirect( $redirect_to, $request, $user ) {
	// Check that we have a user and also that the user has a membership
	if ( ! empty( $user ) && ! empty( $user->ID ) && function_exists( 'pmpro_getMembershipLevelForUser' ) ) {
		// Get the level so we can use for redirect
		$level = pmpro_getMembershipLevelForUser( $user->ID );

		if ( ! empty( $request ) ) {
			$redirect_to = $request;
		}
	}

	return $redirect_to;
}

// add_filter( 'login_redirect', 'a_login_auth_redirect', 10, 3 );
