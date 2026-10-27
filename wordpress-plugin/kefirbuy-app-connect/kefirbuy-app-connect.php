<?php
/**
 * Plugin Name:       KefirBuy App Connect
 * Description:       Lets the KefirBuy Android app sign customers in and show their orders, addresses and profile inside the app. Adds a small, secure REST API under /wp-json/kefirbuy-app/v1/.
 * Version:           1.0.0
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            KefirBuy
 * Text Domain:       kefirbuy-app-connect
 * WC requires at least: 8.0
 *
 * How it works
 * - The app signs in with the customer's normal kefirbuy.com email/username and password.
 * - The plugin returns a random app token. Only a keyed hash of it is stored (user meta), it expires
 *   after 90 days, and it is sent by the app in the "X-KB-Token" header.
 * - With that header, WordPress treats the request as the signed-in customer, so orders placed through
 *   the WooCommerce Store API from the app are attached to the customer's account.
 * - Login and order-tracking attempts are rate limited per IP address.
 */

defined( 'ABSPATH' ) || exit;

final class KB_App_Connect {
	const VERSION   = '1.0.0';
	const NS        = 'kefirbuy-app/v1';
	const META      = '_kb_app_tokens';
	const TTL       = 7776000; // 90 days
	const MAX_TOKENS = 10;     // devices per customer

	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
		add_filter( 'determine_current_user', array( __CLASS__, 'auth_from_header' ), 20 );
		add_action( 'before_woocommerce_init', function () {
			if ( class_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil' ) ) {
				\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', __FILE__, true );
			}
		} );
	}

	/* ------------------------------------------------------------------ tokens */

	private static function hash( $secret ) {
		return hash_hmac( 'sha256', $secret, wp_salt( 'auth' ) );
	}

	private static function issue_token( $user_id, $device = '' ) {
		$secret = wp_generate_password( 40, false, false );
		$tokens = self::tokens( $user_id );
		$tokens[ self::hash( $secret ) ] = array(
			'exp'    => time() + self::TTL,
			'device' => sanitize_text_field( substr( (string) $device, 0, 80 ) ),
			'last'   => time(),
		);
		// Keep the newest MAX_TOKENS
		uasort( $tokens, function ( $a, $b ) { return $b['last'] - $a['last']; } );
		$tokens = array_slice( $tokens, 0, self::MAX_TOKENS, true );
		update_user_meta( $user_id, self::META, $tokens );
		return $user_id . '.' . $secret;
	}

	private static function tokens( $user_id ) {
		$t = get_user_meta( $user_id, self::META, true );
		if ( ! is_array( $t ) ) {
			return array();
		}
		$now = time();
		return array_filter( $t, function ( $row ) use ( $now ) { return is_array( $row ) && isset( $row['exp'] ) && $row['exp'] > $now; } );
	}

	/** Returns the user ID for a valid "X-KB-Token" header, or 0. */
	private static function user_from_token( $raw ) {
		if ( ! is_string( $raw ) || ! preg_match( '/^(\d+)\.([A-Za-z0-9]{40})$/', $raw, $m ) ) {
			return 0;
		}
		$uid    = (int) $m[1];
		$tokens = self::tokens( $uid );
		$h      = self::hash( $m[2] );
		if ( ! isset( $tokens[ $h ] ) ) {
			return 0;
		}
		if ( time() - (int) $tokens[ $h ]['last'] > HOUR_IN_SECONDS ) { // refresh "last used" at most hourly
			$tokens[ $h ]['last'] = time();
			update_user_meta( $uid, self::META, $tokens );
		}
		return $uid;
	}

	private static function header_token() {
		if ( ! empty( $_SERVER['HTTP_X_KB_TOKEN'] ) ) {
			return trim( wp_unslash( $_SERVER['HTTP_X_KB_TOKEN'] ) );
		}
		return '';
	}

	private static function is_rest_request() {
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path   = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$prefix = '/' . trim( rest_get_url_prefix(), '/' ) . '/';
		$home   = rtrim( (string) wp_parse_url( home_url(), PHP_URL_PATH ), '/' ); // WordPress in a subfolder
		if ( 0 === strpos( $path, $home . $prefix ) ) {
			return true;
		}
		$script = basename( $path );
		return isset( $_GET['rest_route'] ) && ( '' === $script || 'index.php' === $script || $home === rtrim( $path, '/' ) ); // phpcs:ignore WordPress.Security.NonceVerification
	}

	/** Sign the request in as the app customer (REST API requests only). */
	public static function auth_from_header( $user_id ) {
		if ( $user_id ) {
			return $user_id;
		}
		$raw = self::header_token();
		if ( '' === $raw || ! self::is_rest_request() ) {
			return $user_id;
		}
		$uid = self::user_from_token( $raw );
		return $uid ? $uid : $user_id;
	}

	private static function revoke( $user_id, $raw ) {
		if ( preg_match( '/^\d+\.([A-Za-z0-9]{40})$/', (string) $raw, $m ) ) {
			$tokens = self::tokens( $user_id );
			unset( $tokens[ self::hash( $m[1] ) ] );
			update_user_meta( $user_id, self::META, $tokens );
		}
	}

	/* ------------------------------------------------------------- rate limits */

	private static function ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0';
		return $ip;
	}

	/** Returns a WP_Error when too many attempts were made from this IP for $action. */
	private static function limited( $action, $max, $window ) {
		$key  = 'kb_rl_' . $action . '_' . md5( self::ip() );
		$hits = (int) get_transient( $key );
		if ( $hits >= $max ) {
			return new WP_Error( 'kb_too_many', __( 'Too many attempts. Please wait a few minutes and try again.', 'kefirbuy-app-connect' ), array( 'status' => 429 ) );
		}
		set_transient( $key, $hits + 1, $window );
		return false;
	}

	private static function clear_limit( $action ) {
		delete_transient( 'kb_rl_' . $action . '_' . md5( self::ip() ) );
	}

	/* ----------------------------------------------------------------- routes */

	public static function routes() {
		$public = '__return_true';
		$authed = function () { return is_user_logged_in(); };
		$r      = function ( $path, $method, $cb, $perm, $args = array() ) {
			register_rest_route( self::NS, $path, array( 'methods' => $method, 'callback' => array( __CLASS__, $cb ), 'permission_callback' => $perm, 'args' => $args ) );
		};
		$r( '/ping', 'GET', 'ping', $public );
		$r( '/login', 'POST', 'login', $public, array(
			'login'    => array( 'required' => true, 'type' => 'string' ),
			'password' => array( 'required' => true, 'type' => 'string' ),
			'device'   => array( 'type' => 'string' ),
		) );
		$r( '/register', 'POST', 'register', $public, array(
			'name'     => array( 'required' => true, 'type' => 'string' ),
			'email'    => array( 'required' => true, 'type' => 'string' ),
			'phone'    => array( 'type' => 'string' ),
			'password' => array( 'required' => true, 'type' => 'string' ),
			'device'   => array( 'type' => 'string' ),
		) );
		$r( '/password/lost', 'POST', 'lost_password', $public, array( 'login' => array( 'required' => true, 'type' => 'string' ) ) );
		$r( '/track', 'POST', 'track', $public, array(
			'order' => array( 'required' => true, 'type' => 'string' ),
			'email' => array( 'required' => true, 'type' => 'string' ),
		) );
		$r( '/logout', 'POST', 'logout', $authed );
		$r( '/me', 'GET', 'me', $authed );
		$r( '/me', 'POST', 'update_me', $authed );
		$r( '/me/password', 'POST', 'change_password', $authed );
		$r( '/me/address', 'POST', 'update_address', $authed );
		$r( '/me/delete', 'POST', 'delete_request', $authed );
		$r( '/orders', 'GET', 'orders', $authed );
		$r( '/orders/(?P<id>\d+)', 'GET', 'order', $authed );
	}

	public static function ping() {
		return array(
			'ok'           => true,
			'version'      => self::VERSION,
			'registration' => 'yes' === get_option( 'woocommerce_enable_myaccount_registration', 'yes' ),
			'woocommerce'  => class_exists( 'WooCommerce' ),
		);
	}

	/* ------------------------------------------------------------- sign in/up */

	public static function login( WP_REST_Request $req ) {
		$limit = self::limited( 'login', 8, 15 * MINUTE_IN_SECONDS );
		if ( $limit ) {
			return $limit;
		}
		$login = trim( (string) $req['login'] );
		$user  = wp_authenticate( $login, (string) $req['password'] );
		if ( is_wp_error( $user ) ) {
			return new WP_Error( 'kb_login_failed', __( 'Wrong email or password.', 'kefirbuy-app-connect' ), array( 'status' => 401 ) );
		}
		self::clear_limit( 'login' );
		do_action( 'kefirbuy_app_login', $user->ID );
		return array( 'token' => self::issue_token( $user->ID, $req['device'] ), 'user' => self::profile( $user->ID ) );
	}

	public static function register( WP_REST_Request $req ) {
		$limit = self::limited( 'register', 5, HOUR_IN_SECONDS );
		if ( $limit ) {
			return $limit;
		}
		if ( 'yes' !== get_option( 'woocommerce_enable_myaccount_registration', 'yes' ) ) {
			return new WP_Error( 'kb_registration_off', __( 'New accounts are not open right now.', 'kefirbuy-app-connect' ), array( 'status' => 403 ) );
		}
		$email = sanitize_email( (string) $req['email'] );
		$name  = sanitize_text_field( (string) $req['name'] );
		$phone = sanitize_text_field( (string) $req['phone'] );
		$pass  = (string) $req['password'];
		if ( ! is_email( $email ) ) {
			return new WP_Error( 'kb_bad_email', __( 'Enter a valid email address.', 'kefirbuy-app-connect' ), array( 'status' => 400 ) );
		}
		if ( strlen( $pass ) < 8 ) {
			return new WP_Error( 'kb_weak_password', __( 'Use a password of at least 8 characters.', 'kefirbuy-app-connect' ), array( 'status' => 400 ) );
		}
		if ( email_exists( $email ) ) {
			return new WP_Error( 'kb_email_exists', __( 'An account with this email already exists. Sign in instead.', 'kefirbuy-app-connect' ), array( 'status' => 409 ) );
		}
		$uid = wc_create_new_customer( $email, '', $pass, array( 'first_name' => $name ) );
		if ( is_wp_error( $uid ) ) {
			return new WP_Error( 'kb_register_failed', wp_strip_all_tags( $uid->get_error_message() ), array( 'status' => 400 ) );
		}
		$c = new WC_Customer( $uid );
		$c->set_billing_first_name( $name );
		$c->set_billing_email( $email );
		$c->set_billing_country( 'PK' );
		if ( $phone ) {
			$c->set_billing_phone( $phone );
		}
		$c->save();
		return array( 'token' => self::issue_token( $uid, $req['device'] ), 'user' => self::profile( $uid ) );
	}

	public static function lost_password( WP_REST_Request $req ) {
		$limit = self::limited( 'lost', 5, HOUR_IN_SECONDS );
		if ( $limit ) {
			return $limit;
		}
		$login = trim( (string) $req['login'] );
		if ( $login ) {
			retrieve_password( $login ); // sends the standard WordPress reset email when the account exists
		}
		// Same answer either way, so the app never reveals which emails have accounts.
		return array( 'ok' => true, 'message' => __( 'If an account exists for that email, we have sent a link to reset the password.', 'kefirbuy-app-connect' ) );
	}

	public static function logout( WP_REST_Request $req ) {
		self::revoke( get_current_user_id(), self::header_token() );
		return array( 'ok' => true );
	}

	/* ---------------------------------------------------------------- profile */

	private static function addr( WC_Customer $c, $type ) {
		$f   = array( 'first_name', 'last_name', 'address_1', 'address_2', 'city', 'state', 'postcode', 'country', 'phone' );
		$out = array();
		foreach ( $f as $k ) {
			$getter = "get_{$type}_{$k}";
			if ( 'shipping' === $type && 'phone' === $k && ! method_exists( $c, $getter ) ) {
				continue;
			}
			$out[ $k ] = method_exists( $c, $getter ) ? (string) $c->$getter() : '';
		}
		if ( 'billing' === $type ) {
			$out['email'] = (string) $c->get_billing_email();
		}
		return $out;
	}

	private static function profile( $uid ) {
		$u = get_userdata( $uid );
		$c = new WC_Customer( $uid );
		$name = trim( $c->get_first_name() . ' ' . $c->get_last_name() );
		if ( '' === $name ) {
			$name = trim( $c->get_billing_first_name() . ' ' . $c->get_billing_last_name() );
		}
		return array(
			'id'       => (int) $uid,
			'name'     => $name ? $name : $u->display_name,
			'email'    => $u->user_email,
			'phone'    => (string) $c->get_billing_phone(),
			'billing'  => self::addr( $c, 'billing' ),
			'shipping' => self::addr( $c, 'shipping' ),
			'since'    => $u->user_registered,
		);
	}

	public static function me() {
		return self::profile( get_current_user_id() );
	}

	public static function update_me( WP_REST_Request $req ) {
		$uid = get_current_user_id();
		$u   = get_userdata( $uid );
		$c   = new WC_Customer( $uid );
		if ( isset( $req['name'] ) ) {
			$name = sanitize_text_field( (string) $req['name'] );
			if ( '' === $name ) {
				return new WP_Error( 'kb_name', __( 'Enter your full name.', 'kefirbuy-app-connect' ), array( 'status' => 400 ) );
			}
			$c->set_first_name( $name );
			$c->set_last_name( '' );
			$c->set_display_name( $name );
		}
		if ( isset( $req['phone'] ) ) {
			$c->set_billing_phone( sanitize_text_field( (string) $req['phone'] ) );
		}
		if ( isset( $req['email'] ) && strtolower( (string) $req['email'] ) !== strtolower( $u->user_email ) ) {
			$email = sanitize_email( (string) $req['email'] );
			if ( ! is_email( $email ) ) {
				return new WP_Error( 'kb_bad_email', __( 'Enter a valid email address.', 'kefirbuy-app-connect' ), array( 'status' => 400 ) );
			}
			if ( ! wp_check_password( (string) $req['current_password'], $u->user_pass, $uid ) ) {
				return new WP_Error( 'kb_password', __( 'Enter your current password to change your email.', 'kefirbuy-app-connect' ), array( 'status' => 403 ) );
			}
			if ( email_exists( $email ) ) {
				return new WP_Error( 'kb_email_exists', __( 'That email is already used by another account.', 'kefirbuy-app-connect' ), array( 'status' => 409 ) );
			}
			$c->set_email( $email );
		}
		$c->save();
		return self::profile( $uid );
	}

	public static function change_password( WP_REST_Request $req ) {
		$uid = get_current_user_id();
		$u   = get_userdata( $uid );
		$new = (string) $req['new_password'];
		if ( ! wp_check_password( (string) $req['current_password'], $u->user_pass, $uid ) ) {
			return new WP_Error( 'kb_password', __( 'Your current password is not correct.', 'kefirbuy-app-connect' ), array( 'status' => 403 ) );
		}
		if ( strlen( $new ) < 8 ) {
			return new WP_Error( 'kb_weak_password', __( 'Use a password of at least 8 characters.', 'kefirbuy-app-connect' ), array( 'status' => 400 ) );
		}
		wp_set_password( $new, $uid );           // signs out website sessions
		delete_user_meta( $uid, self::META );     // and every app device
		return array( 'ok' => true, 'token' => self::issue_token( $uid, 'password change' ) );
	}

	public static function update_address( WP_REST_Request $req ) {
		$type = 'shipping' === $req['type'] ? 'shipping' : 'billing';
		$f    = (array) $req['fields'];
		$c    = new WC_Customer( get_current_user_id() );
		$keys = array( 'first_name', 'last_name', 'address_1', 'address_2', 'city', 'state', 'postcode', 'country', 'phone' );
		foreach ( $keys as $k ) {
			if ( ! array_key_exists( $k, $f ) ) {
				continue;
			}
			$setter = "set_{$type}_{$k}";
			if ( method_exists( $c, $setter ) ) {
				$c->$setter( sanitize_text_field( (string) $f[ $k ] ) );
			}
		}
		if ( 'billing' === $type && ! empty( $f['email'] ) ) {
			$e = sanitize_email( (string) $f['email'] );
			if ( is_email( $e ) ) {
				$c->set_billing_email( $e );
			}
		}
		$c->save();
		return self::profile( get_current_user_id() );
	}

	/** Google Play requires apps with sign-up to offer account deletion. This uses WordPress's built-in
	 *  privacy request: the customer confirms by email, then the shop owner completes it in Tools → Erase Personal Data. */
	public static function delete_request( WP_REST_Request $req ) {
		$uid = get_current_user_id();
		$u   = get_userdata( $uid );
		if ( ! wp_check_password( (string) $req['password'], $u->user_pass, $uid ) ) {
			return new WP_Error( 'kb_password', __( 'Your password is not correct.', 'kefirbuy-app-connect' ), array( 'status' => 403 ) );
		}
		$rid = wp_create_user_request( $u->user_email, 'remove_personal_data' );
		if ( is_wp_error( $rid ) && 'duplicate_request' !== $rid->get_error_code() ) {
			return new WP_Error( 'kb_delete_failed', wp_strip_all_tags( $rid->get_error_message() ), array( 'status' => 400 ) );
		}
		if ( ! is_wp_error( $rid ) ) {
			wp_send_user_request( $rid );
		}
		return array( 'ok' => true, 'message' => __( 'We have emailed you a link to confirm. After you confirm, your account and personal data will be deleted.', 'kefirbuy-app-connect' ) );
	}

	/* ----------------------------------------------------------------- orders */

	private static function order_summary( WC_Order $o ) {
		$items = array();
		foreach ( $o->get_items() as $item ) {
			$items[] = array( 'name' => $item->get_name(), 'qty' => (int) $item->get_quantity(), 'product_id' => (int) $item->get_product_id() );
		}
		$created = $o->get_date_created();
		return array(
			'id'          => $o->get_id(),
			'number'      => (string) $o->get_order_number(),
			'status'      => $o->get_status(),
			'status_name' => wc_get_order_status_name( $o->get_status() ),
			'date'        => $created ? $created->date( 'c' ) : '',
			'total'       => (float) $o->get_total(),
			'currency'    => $o->get_currency(),
			'payment'     => $o->get_payment_method_title(),
			'items'       => $items,
		);
	}

	public static function orders( WP_REST_Request $req ) {
		$orders = wc_get_orders( array(
			'customer_id' => get_current_user_id(),
			'limit'       => 50,
			'orderby'     => 'date',
			'order'       => 'DESC',
			'status'      => array_keys( wc_get_order_statuses() ),
		) );
		return array_map( array( __CLASS__, 'order_summary' ), $orders );
	}

	public static function order( WP_REST_Request $req ) {
		$o = wc_get_order( (int) $req['id'] );
		if ( ! $o || (int) $o->get_customer_id() !== get_current_user_id() ) {
			return new WP_Error( 'kb_not_found', __( 'Order not found.', 'kefirbuy-app-connect' ), array( 'status' => 404 ) );
		}
		$out   = self::order_summary( $o );
		$items = array();
		foreach ( $o->get_items() as $item ) {
			$p     = $item->get_product();
			$img   = $p ? wp_get_attachment_image_url( $p->get_image_id(), 'woocommerce_thumbnail' ) : '';
			$meta  = array();
			foreach ( $item->get_formatted_meta_data() as $m ) {
				$meta[] = wp_strip_all_tags( $m->display_key . ': ' . $m->display_value );
			}
			$items[] = array( 'name' => $item->get_name(), 'qty' => (int) $item->get_quantity(), 'total' => (float) $item->get_total(), 'product_id' => (int) $item->get_product_id(), 'image' => $img ? $img : '', 'meta' => $meta );
		}
		$lines = array();
		foreach ( $o->get_order_item_totals() as $row ) {
			$lines[] = array( 'label' => wp_strip_all_tags( $row['label'] ), 'value' => html_entity_decode( wp_strip_all_tags( $row['value'] ) ) );
		}
		$notes = array();
		foreach ( wc_get_order_notes( array( 'order_id' => $o->get_id(), 'type' => 'customer' ) ) as $n ) {
			$notes[] = array( 'date' => $n->date_created ? $n->date_created->date( 'c' ) : '', 'text' => wp_strip_all_tags( $n->content ) );
		}
		$out['items']        = $items;
		$out['lines']        = $lines;
		$out['notes']        = $notes;
		$out['shipping_to']  = wp_strip_all_tags( str_replace( '<br/>', ', ', (string) $o->get_formatted_shipping_address( $o->get_formatted_billing_address() ) ) );
		$out['customer_note'] = $o->get_customer_note();
		$out['pay_url']      = $o->needs_payment() ? $o->get_checkout_payment_url() : '';
		$out['view_url']     = $o->get_checkout_order_received_url();
		return $out;
	}

	/** Public order tracking: order number + the billing email used on the order. */
	public static function track( WP_REST_Request $req ) {
		$limit = self::limited( 'track', 15, 15 * MINUTE_IN_SECONDS );
		if ( $limit ) {
			return $limit;
		}
		$num   = preg_replace( '/[^0-9]/', '', (string) $req['order'] );
		$email = strtolower( trim( (string) $req['email'] ) );
		$o     = $num ? wc_get_order( (int) $num ) : false;
		if ( ! $o ) { // custom order-number plugins
			$found = wc_get_orders( array( 'limit' => 1, 'meta_key' => '_order_number', 'meta_value' => $num ) ); // phpcs:ignore WordPress.DB.SlowDBQuery
			$o     = $found ? $found[0] : false;
		}
		if ( ! $o || strtolower( $o->get_billing_email() ) !== $email ) {
			return new WP_Error( 'kb_not_found', __( 'We couldn’t find an order with that number and email.', 'kefirbuy-app-connect' ), array( 'status' => 404 ) );
		}
		$s = self::order_summary( $o );
		unset( $s['id'] );
		return $s;
	}
}

KB_App_Connect::init();
