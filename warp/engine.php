<?php
/**
 * Copyright (c) 2010, WARP Library <abuzaim+warp@gmail.com>
 * All rights reserved.
 */

/**
 * Object: $_CONFIG
 *
 * The global $_CONFIG <Context> object used by some WARP functions.
 */
$GLOBALS['_CONFIG'] = new Context();


/// Note: PHP 5.3 namespacing
///
/// If you're using PHP 5.3, you can enable the 'warp' namespace by
/// uncommenting the "namespace warp" line below. This is disabled by default
/// to keep WARP compatible with older PHP installations.

# namespace warp


	/**
	 * Constant: WARP_COOKIE_NAME
	 *
	 * The default cookie name used by WARP.
	 */
	define('WARP_COOKIE_NAME',  'b89f50');

	/**
	 * Constant: WARP_COOKIE_SALT
	 *
	 * The salt used to calculate the SHA1 hash of cookies.
	 */
	define('WARP_COOKIE_SALT',  '934ea3a36cbcd73f223f0c8161fd03b8');

	/**
	 * Constant: WARP_DEFAULT_SALT
	 *
	 * The salt used to calculate the SHA1 hash of admin passwords.
	 */
	define('WARP_DEFAULT_SALT', 'e9bb80898a2c1e77feb59effb54f12090c58e512');

	/**
	 * Constant: WARP_INCORRECT_PASSWORD
	 *
	 * Used by the Authentication functions to denote failure of login
	 * authentication.
	 */
	define('WARP_INCORRECT_PASSWORD', 0);


/**
 * Core Functions
 * ==============
 */

	/**
	 * Function: init
	 *
	 * Initialize web application with default configuration. Also performs
	 * magic quote removal and session setup.
	 *
	 * Parameters:
	 *     $defaults - Default configuration array.
	 *
	 * Returns:
	 *     The configuration <Context> object.
	 */
	function init($defaults)
	{
		if (function_exists('config_default'))
			$defaults = array_merge(config_default(), $defaults);

		$host   = $_SERVER['SERVER_NAME'];
		$hosts  = config_hosts();
		$config = array();

		foreach ($hosts as $id => $names) {
			if (in_array($host, $names))  {
				$fn = "config_$id";
				if (function_exists($fn)) {
					$config = call_user_func($fn);
					break;
				}
			}
		}
		$config = array_merge($defaults, $config);
		$config = new Context($config);

		if (get_magic_quotes_gpc()) {
			$_POST    = fix_slashes($_POST);
			$_GET     = fix_slashes($_GET);
			$_REQUEST = fix_slashes($_REQUEST);
			$_COOKIE  = fix_slashes($_COOKIE);
		}

		if ($config->session_name)
			session_name($config->session_name);

		session_set_cookie_params(
			$config->auth_lifetime__or(60*60*24*30),
			$config->auth_path__or('/'),
			$config->auth_domain
		);
		session_start();

		return $config;
	}

	/**
	 * Function: load
	 *
	 * Load a PHP file and return its output.
	 *
	 * Parameters:
	 *     $filename - The PHP file path.
	 *     $self     - The <Context> object to pass to the PHP file.
	 *
	 * Returns:
	 *     An array of callbacks to use to filter the output.
	 */
	function load($filename, &$self=null, $filters=array())
	{
		if (!$self)
			$self = new Context();

		if (isset($self->config))
			$config = $self->config;

		if (isset($self->db))
			$db = $self->db;

		ob_start();
			include $filename;
			$content = ob_get_contents();
		ob_end_clean();

		if (is_array($filters) && count($filters))
			foreach ($filters as $fn)
				if (is_callable($fn)) $content = $fn($content);

		return $content;
	}


/**
 * String utilities
 * ================
 */

	/**
	 * Function: clean_filename
	 *
	 * Cleans a given filename, makes sure the filename has no directory
	 * traversal (e.g. "name/../dir/name/") and normalizes directory separators.
	 *
	 * Parameters:
	 *     $filename          - The filename string.
	 *     $underscore_hidden - If true, the filename given will be
	 *                          considered invalid if it starts with
	 *                          an underscore. Default true.
	 *
	 * Returns:
	 *     If the filename has '..' traversals, or starts with an
	 *     underscore (and if the $underscore_hidden parameter is set to
	 *     true), returns an empty string. Otherwise, it returns the
	 *     filename with directory separators normalized to use the
	 *     current operating system's.
	 */
	function clean_filename($filename, $underscore_hidden=true)
	{
		if (strpos($filename, '..') !== false)
			return '';

		$filename = trim(
			str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $filename),
			' '.DIRECTORY_SEPARATOR
		);

		if ($underscore_hidden) {
			$parts = explode(DIRECTORY_SEPARATOR, $filename);
			foreach ($parts as $p)
				if ($p && $p{0} == '_') return '';
		}

		return $filename;
	}

	/**
	 * Function: fix_slashes
	 *
	 * Applies stripslashes to given string or an array recursively.
	 *
	 * Parameters:
	 *     $arr - The string or array to fix.
	 *
	 * Returns:
	 *     The fixed string or array.
	 */
	function fix_slashes($arr='')
	{
		if (is_null($arr) || $arr == '') return null;
		if (!get_magic_quotes_gpc()) return $arr;
		return is_array($arr) ? array_map('fix_slashes', $arr) : stripslashes($arr);
	}

	/**
	 * Function: tpl
	 *
	 * Simple string templating.
	 *
	 * Parameters:
	 *     $tpl    - The template string. Template keys are marked like:
	 *               {key} and will be substituted with the given value
	 *               from the $params array.
	 *     $params - Template key-value parameters.
	 *
	 * Returns:
	 *     The string generated from the template substitution.
	 */
	function tpl($tpl, $params)
	{
		$ps = array();
		foreach ($params as $key => $value) {
			$ps["\{$key\}"] = $value;
		}
		return str_replace(array('{','}'), '', strtr($tpl, $ps));
	}

	/**
	 * Function: tidy_str
	 *
	 * Use HTML Tidy to clean and repair HTML strings.
	 *
	 * Uses the $_CONFIG global <Context> object.
	 *
	 * Configuration:
	 *     tidy_html   - If FALSE, this function does nothing. Default TRUE.
	 * 	   tidy_config - Tidy options to use. Defaults to an empty array.
	 *
	 * Parameters:
	 *     $str - The HTML string to tidy.
	 *
	 * Returns:
	 *     The tidied HTML string.
	 */
	function tidy_str($str)
	{
		global $_CONFIG;
		if ($_CONFIG->tidy_html__or(true)) {
			$tidy = new tidy();
			$tidy->parseString($str, $_CONFIG->tidy_config__or(array()));
			if ($tidy->cleanRepair()) {
				fb(tidy_get_error_buffer($tidy), 'Tidy Errors');
				return (string)$tidy;
			}
		}
		return $str;
	}

/**
 * URI and URLs
 * ============
 */

	/**
	 * Function: get_uri
	 *
	 * Gets the current request URI.
	 *
	 * This is the application's request URI, not the HTTP (i.e. not
	 * $_SERVER['REQUEST_URI'). This can be used to determine an application
	 * controller method, for instance.
	 *
	 * Garners the request URI via 4 methods, each tried in order:
	 * (the request URI is marked as [the/request/uri], the brackets are not
	 * literal)
	 *
	 *     1. From the PATH_INFO value:
	 *        example.com/index.php/[the/request/uri]?extra=keys
	 *
	 *     2. From a GET query parameter:
	 *        example.com/index.php?uri=[the/request/uri]&extra=keys
	 *
	 *     3. From the first parameter in a GET query:
	 *        example.com/index.php?[the/request/uri]&extra=keys
	 *
	 *     4. From the whole query string:
	 *        example.com/index.php[the/request/uri&extra=keys]
	 *
	 * Note that in method 4, extra keys are included in the URI.
	 *
	 * Parameters:
	 *     $get_var - The GET variable name to use.
	 *
	 * Parameters:
	 *     The requested URI, or an empty string if none is found.
	 */
	function get_uri($get_var='p')
	{
		// 1. Try to get request URI from $_SERVER['PATH_INFO']
		$path_info = isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : @getenv('PATH_INFO');
		$path_info = trim($path_info, '/');
		if ($path_info)
			return $path_info;

		// 2. From $_GET[$get_var]
		$path_get = '';
		if (isset($_GET[$get_var])) {
			$path_get = $_GET[$get_var];
		}

		// 3. From the first $_GET key if the key's value is none, this is so
		//    that requests to things like "index.php?name/of/page&var=x&key=y"
		//    works properly.
		else {
			if (count($_GET)) {
				$key = key($_GET);
				$val = $_GET[$key];
				if ($val == '') {
					$path_get = $key;
				}
			}
		}
		$path_get = trim($path_get, '/');
		if ($path_get)
			return $path_get;

		// 4. From the whole QUERY_STRING
		$path_qs = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : @getenv('QUERY_STRING');
		$path_qs = trim($path_qs, '/');
		if ($path_qs)
			return $path_qs;

		return '';
	}

	/**
	 * Function: url
	 *
	 * Gets an absolute application URL based on the given request URI.
	 *
	 * Uses the $_CONFIG global <Context> object.
	 *
	 * Configuration:
	 *     uri_method - The method to use to garner the request URI. Either
	 *                  'PATH_INFO', 'GET_VAR', or 'QUERY_STRING'. Defaults
	 *                  to 'PATH_INFO'. See <get_uri>
	 *     get_var    - The GET parameter name to use to get the request URI.
	 *     base_url   - The web application's base url.
	 *
	 * Parameters:
	 *     $uri    - The request URI to get the absolute URL for.
	 *     $append - Any extra query string to append to the URL (in the format
	 *               of 'key=value&key2=value2')
	 *
	 * Returns:
	 *     The absolute URL.
	 */
	function url($uri, $append='')
	{
		global $_CONFIG;

		$method   = $_CONFIG->uri_method__or('PATH_INFO');
		$get_var  = $_CONFIG->get_var__or('p');
		$base_url = $_CONFIG->base_url;
		$base_url = rtrim($base_url, '/').'/index.php';

		$sep = array(
			'PATH_INFO'    => '?',
			'GET_VAR'      => '&',
			'QUERY_STRING' => ''
		);
		$sep = isset($sep[$method]) ? $sep[$method] : '';
		$append = ($sep && $append) ? $sep.$append  : '';

		$urls = array(
			'PATH_INFO'    => "{$base_url}/{$uri}{$append}",
			'GET_VAR'      => "{$base_url}?$get_var=$uri{$append}",
			'QUERY_STRING' => "{$base_url}?$uri"
		);

		if (!isset($urls[$method]))
			$method = 'GET_VAR';

		return $urls[$method];
	}

	/**
	 * Function: redirect
	 *
	 * Redirects to given URL.
	 *
	 * Function will exit if the redirect fails somehow.
	 *
	 * Parameters:
	 *     $url - The URL.
	 */
	function redirect($url=null)
	{
		if (is_null($url))
			$url = $_SERVER['PHP_SELF'];
		header("Location: $url");
		exit();
	}

	/**
	 * Function: redirect_uri
	 *
	 * Redirects to given URI's absolute URL.
	 *
	 * Parameters:
	 *     $uri - The URI.
	 */
	function redirect_uri($uri)
	{
		redirect(url($uri));
	}


/**
 * Session utilities
 * =================
 */

	/**
	 * Function: set_message
	 *
	 * Sets a cross-request "flash" message.
	 *
	 * Parameters:
	 *     $msg - The message to set.
	 *     $url - If set, will automatically redirect to the URL once message is set.
	 */
	function set_message($msg, $url='')
	{
		$_SESSION['message'] = $msg;
		if ($url)
			redirect($url);
	}

	/**
	 * Function: get_message
	 *
	 * Gets a "flash" message set from a previous page.
	 *
	 * Parameters:
	 *     $default - A default message if no message is actually set.
	 *
	 * Returns:
	 *     The message (not in a bottle)
	 */
	function get_message($default='')
	{
		$msg = isset($_SESSION['message']) ? $_SESSION['message'] : $default;
		unset($_SESSION['message']);
		return $msg;
	}


/**
 * Authentication
 * ==============
 */

	/**
	 * Function: authenticate
	 *
	 * Authenticates given password.
	 *
	 * Uses the $_CONFIG global <Context> object.
	 *
	 * Configuration:
	 *     auth_hash_salt - The hash salt to use, if not set, uses a default one.
	 *
	 * Parameters:
	 *     $password - The password either in plain text, or hashed.
	 *
	 * Returns:
	 *     TRUE if the password is the same as in the configuration
	 */
	function authenticate($password, $hashed=false)
	{
		global $_CONFIG;

		$hash_salt     = $_CONFIG->auth_hash_salt__or(WARP_DEFAULT_SALT);
		$user_password = $hashed ? $password : sha1($password.$hash_salt);

		return ($user_password == get_config_password());
	}

	/**
	 * Function: authenticate_from_post
	 *
	 * Authenticates password from a POST request.
	 *
	 * Expects a single POST variable, 'password' containing the password in
	 * plain text.
	 *
	 * Parameters:
	 *     $success_page - The URI to redirect to if successful
	 *
	 * Returns:
	 *     FALSE                   - If no POST form is submitted
	 *     WARP_INCORRECT_PASSWORD - If the authentication failed
	 */
	function authenticate_from_post($success_page)
	{
		$post = new Context($_POST);
		if ($post->password) {
			if (authenticate($post->password)) {
				authenticate_session();
				return redirect(url($success_page));
			}
			return WARP_INCORRECT_PASSWORD;
		}
		return false;
	}

	/**
	 * Function: require_login
	 *
	 * Checks if current session is authenticated.
	 *
	 * Uses the $_CONFIG global <Context> object.
	 *
	 * Configuration:
	 *     auth_cookie_name - The name of the cookie WARP uses, defaults to an internal name.
	 *     auth_cookie_salt - The salt used to hash the cookie value for security, defaults to an internal salt.
	 *
	 * Parameters:
	 *     $login   - The URI of the login page.
	 *     $success - The URI of the success page.
	 *
	 * Returns:
	 *
	 *     If logged in, function will redirect to $success, if it is set,
	 *     otherwise it will return TRUE.
	 *
	 *     If NOT logged in, function will redirect to $login, if it is set,
	 *     otherwise it will return FALSE.
	 */
	function require_login($login=null, $success=null)
	{
		global $_CONFIG;

		$session = new Context($_SESSION);
		if ($session->password && authenticate($session->password, true)) {
			return $success ? redirect(url($success)) : true;
		}

		$cookie_name = $_CONFIG->auth_cookie_name__or(WARP_COOKIE_NAME);
		$cookie_salt = $_CONFIG->auth_cookie_salt__or(WARP_COOKIE_SALT);
		$cookie = new Context($_COOKIE);

		if ($cookie->$cookie_name) {
			$cookie_pass = $cookie->$cookie_name;
			$config_pass = sha1(get_config_password().$cookie_salt);
			if ($cookie_pass == $config_pass) {
				return $success ? redirect(url($success)) : true;
			}
		}

		return $login ? redirect(url($login)) : false;
	}

	/**
	 * Function: is_logged_in
	 *
	 * Alias to <require_login>, without any login or success URIs (always
	 * returns the boolean result)
	 */
	function is_logged_in()
	{
		return require_login();
	}

	/**
	 * Function: get_config_password
	 *
	 * Gets the configured password.
	 *
	 * Password is hashed using SHA1 and default salt.
	 *
	 * Uses the $_CONFIG global configuration object.
	 *
	 * Configuration:
	 *     auth_hash_salt  - The hash salt to use, if not set, uses a default one.
	 *     admin_password  - The admin password. No default is used hence if one
	 *                       is not set, anybody can authenticate the session.
	 *     password_hashed - TRUE, if the 'admin_password' is already hashed.
	 */
	function get_config_password()
	{
		global $_CONFIG;

		$hash_salt = $_CONFIG->auth_hash_salt__or(WARP_DEFAULT_SALT);
		return $_CONFIG->password_hashed ? $_CONFIG->admin_password : sha1($_CONFIG->admin_password.$hash_salt);
	}

	/**
	 * Function: authenticate_session
	 *
	 * Authenticates the current session (sets session and cookie tokens)
	 *
	 * Uses the $_CONFIG global configuration object.
	 *
	 * Configuration:
	 *     auth_domain      - The cookie domain WARP uses to set cookies and sessions. Default ''.
	 *     auth_path        - The cookie path. Default '/'.
	 *     auth_lifetime    - The cookie expire lifetime in seconds. Defaults to 30 days.
	 *     auth_cookie_name - The cookie name. Defaults to an internal one.
	 *     auth_cooke_salt  - The cookie salt used to hash cookie values.
	 */
	function authenticate_session()
	{
		global $_CONFIG;

		$cookie_host = $_CONFIG->auth_domain;
		$cookie_path = $_CONFIG->auth_path__or('/');
		$cookie_life = $_CONFIG->auth_lifetime__or(60*60*24*30);
		$cookie_name = $_CONFIG->auth_cookie_name__or(WARP_COOKIE_NAME);
		$cookie_salt = $_CONFIG->auth_cookie_salt__or(WARP_COOKIE_SALT);

		$password = get_config_password();
		$_SESSION['password'] = $password;

		return setcookie($cookie_name, sha1($password.$cookie_salt), time()+$cookie_life, $cookie_path, $cookie_host);
	}

	/**
	 * Function: logout
	 *
	 * Logs out the current session.
	 *
	 * Uses the $_CONFIG global configuration object.
	 *
	 * Configuration:
	 *     auth_domain      - The cookie domain WARP uses to set cookies and sessions. Default ''.
	 *     auth_path        - The cookie path. Default '/'.
	 *     auth_cookie_name - The cookie name. Default is an internal one.
	 *     base_url         - The web application's base url. Default ''.
	 *
	 * Parameters:
	 *     $uri - The URI to redirect to once logged out. If null, will not
	 *            redirect anywhere.
	 */
	function logout($uri=null)
	{
		global $_CONFIG;

		$_SESSION['password'] = '';

		$cookie_host = $_CONFIG->auth_domain;
		$cookie_path = $_CONFIG->auth_path__or('/');
		$cookie_name = $_CONFIG->auth_cookie_name__or(WARP_COOKIE_NAME);

		if (setcookie($cookie_name, '', time() - 3600, $cookie_path, $cookie_host)) {
			redirect($_CONFIG->base_url);
		}
		return true;
	}

	/**
	 * Class: Context
	 *
	 * Class that adds functionality to use default values when accessing
	 * undefined object properties.
	 *
	 * Can be used to set up configuration options with default values, for example.
	 *
	 * Default properties:
	 *
	 *     Context property values can be passed as an array to the
	 *     constructor, or manually assigned to the instantiated object as
	 *     normal.
	 *
	 *     > $obj = new Context(array('name' => 'value'));
	 *     > $obj->another_key = 'value';
	 *     > $obj->welcome = 'to the jungle';
	 *
	 *     Default or fallback values can be specified during call-time by
	 *     calling the special '__or' spec (also see the 'specs' section below)
	 *
	 *     > echo $obj->hello;                  // outputs nothing
	 *     > echo $obj->hello__or('konichiwa'); // outputs 'konichiwa'
	 *
	 * Undefined properties:
	 *
	 *     An empty string '' is returned when accessing undefined properties.
	 *     No PHP Warning is raised.
	 *
	 *     > $obj = new Context();
	 *     > echo $obj->non_existent_key;  // outputs nothing
	 *
	 * Callables:
	 *
	 *     The Context class automatically converts properties that are
	 *     callables into methods.
	 *
	 *     > $obj = new Context();
	 *     > $obj->my_trim = 'trim';
	 *     > echo $obj->my_trim;            // outputs 'trim'
     *     > echo $obj->my_trim('  text '); // outputs 'text'
	 *
	 *     Using PHP 5.3 closures.
	 *
	 *     > $obj->run = function($name) {
	 *     >     echo "Run, $name, run!";
	 *     > };
	 *     > echo $obj->run;          // outputs an array describing the colsure
	 *     > echo $obj->run('Forest') // outputs 'Run, Forest, run!'
	 *
	 * Property specs:
	 *
	 *     Object properties can also be retreived and filtered using special
	 *     '__' spec methods:
	 *
	 *     > $obj = new Context();
	 *     >
	 *     > // or: returns the default value if property is undefined
	 *     > $obj->does_not_exist__or('default value');
	 *     >
	 *     > // escape: returns the value html-escaped using htmlspecialchars.
	 *     > $obj->unsafe_html__escape();
	 *     >
	 *     > // uppercase, lowercase: returns the value uppercased or lowercased
	 *     > $obj->text__uppercase();
	 *     >
	 *     > // format: formats the value using WARP's <tpl> function
	 *     > $obj->template = 'hello, my name is {name} and I am a {addiction}';
	 *     > $obj->template__format(array('name'=>'David', 'addiction'=>'sexaholic'));
	 */
	class Context extends stdClass
	{
		public function __construct($context=array())
		{
			foreach ($context as $k => $v)
				$this->$k = $v;
		}

		public function __get($name)
		{
			return '';
		}

		public function __call($name, $args)
		{
			if (!empty($this->$name) && is_callable($this->$name))
				return call_user_func_array($this->$name, $args);

			$specs = array();;
			$value = '';

			if (($s = strpos($name, '__')) !== false) {
				$specs = array_slice(explode('__', $name), 1);
				$name  = substr($name, 0, $s);
			}

			$value = isset($this->$name) ? $this->$name : '';

			if ($specs) {
				foreach ($specs as $spec) {
					$fn = array($this, "spec_$spec");
					if (is_callable($fn))
						$val = call_user_func($fn, $name, $value, $args);
						if (!is_null($val))
							$value = $val;
				}
			}

			return $value;
		}

		protected function spec_or($name, $value, $args)
		{
			if (!empty($value)) {
				return $value;
			}
			else {
				return count($args) ? $args[0] : null;
			}
		}

		protected function spec_escape($name, $value, $args)
		{
			return htmlspecialchars($value);
		}

		protected function spec_uppercase($name, $value, $args)
		{
			return strtoupper($value);
		}

		protected function spec_lowercase($name, $value, $args)
		{
			return strtolower($value);
		}

		protected function spec_format($name, $value, $args)
		{
			if (count($args) && $value) {
				$keys = count($args) ? $args[0] : array();
				return tpl($value, $keys);
			}
			return $value;
		}
	}
