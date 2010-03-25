=============================================
WARP Library
=============================================
---------------------------------------------
The Web Application Rapid Programming library
---------------------------------------------

.. contents::


Introduction
============

WARP is a collection of loosely coupled functions and classes that help
build simple web applications quickly.

Installation
============

WARP is just one file, ``warp/engine.php``. Copy this file (with or without
the ``warp`` directory) into your PHP include path.

Usage
=====

To use the WARP library, just include the ``engine.php`` file in your web
application source::

    <?php
    require_once 'warp/engine.php';

Optionally, initialize the $_CONFIG object::

    $_CONFIG->admin_password = 'secret';
    $_CONFIG->tidy_html = true;

Note that ``$_CONFIG`` is already instantiated in ``warp/engine.php``.

Request URIs
------------

WARP can determine what URI the user is requesting by using the ``get_uri``
function. Note that his is not the HTTP request (not $_SERVER['REQUEST_URI'])
but an application-specific URI string passed via any of these methods:

1. From the PATH_INFO value:
   ``example.com/index.php/the/request/uri?extra=keys``

2. From a GET query parameter:
   ``example.com/index.php?uri=the/request/uri&extra=keys``

3. From the first parameter in a GET query:
   ``example.com/index.php?the/request/uri&extra=keys``

4. From the whole query string:
   ``example.com/index.phpthe/request/uri&extra=keys``

Example
-------

Serving PHP pages::

    <?php
    require_once 'warp/engine.php';

    $_CONFIG->base_url = 'http://example.com/';
    $_CONFIG->pages_path = './pages';

    $page = get_uri();
    $file = $page . '/' . clean_filename($file);

    if (is_file($file)) {
        $content = load($file);
    }

    echo $content;

Simple URI to functions (PHP 5.3+)::

    <?php
    require_once 'warp/engine.php';

    $urls = array(
        'home' => function($context) {
            echo "Welcome to {$context->site_name}";
        },
        'about' => function($context) {
            echo "About Us";
        },
        '404' => function($context) {
            echo "Sorry, page not found: $uri"
        }
    );

    $uri = get_uri();
    $uri = isset($urls[$uri]) ? $uri : '404';

    $context = new Context();
    $context->uri = $uri;
    $context->site_name = 'My Website';
    $context->config = $_CONFIG;

    $urls[$uri]($context);

Configuration
=============

WARP uses an optional global configuration object, ``$_CONFIG``;

It should be an object of the ``Context`` class, documented below.

Some functions require this object. The source documentation for each function
will specifiy if it requires this global object, which configuration options it
expects to use from it, and what default values it uses.

If you want to override any of these default values, initialize the ``$_CONFIG``
object before using any of the WARP functions.

Available onfiguration options
------------------------------

No initial default values are set globally by WARP. Each WARP function that
uses these configuration options will use its own default values, if you have
not set it yourself in ``$_CONFIG``.

``tidy_html``
  If FALSE, this function does nothing.

``tidy_config``
  Tidy options to use.

``uri_method``
  The method to use to garner the request URI. Either 'PATH_INFO', 'GET_VAR',
  or 'QUERY_STRING'. See the ``get_uri`` function.

``get_var``
  The GET parameter name to use to get the request URI.

``base_url``
  The web application's base url.

``auth_hash_salt``
  The hash salt to use for hashing passwords.

``auth_cookie_name``
  The name of the cookie WARP uses.

``auth_cookie_salt``
  The salt used to hash cookie values.

``auth_domain``
  The cookie domain WARP uses to.

``auth_path``
  The cookie path. Default '/'.

``auth_lifetime``
  The cookie expire lifetime in seconds. Defaults to 30 days.

``admin_password``
  An admin password.

``password_hashed``
  If TRUE, WARP treats ``admin_password`` as already hashed.


PHP 5.3 Namespacing
===================

Some WARP function names are generic and might conflict with other libraries or
your own application. If you're using PHP 5.3+, you can enable the ``warp``
namespace by commenting out the line::

    # namespace warp

In the ``warp/engine.php`` file.
