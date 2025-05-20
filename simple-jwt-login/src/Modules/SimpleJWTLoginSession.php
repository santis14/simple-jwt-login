<?php

namespace SimpleJWTLogin\Modules;

use SimpleJWTLogin\Helpers\Jwt\JwtKeyFactory;
use SimpleJWTLogin\Libraries\JWT\JWT;
use SimpleJWTLogin\Modules\Settings\AuthenticationSettings;
use SimpleJWTLogin\Services\AuthenticateService;
use SimpleJWTLogin\Modules\SimpleJWTLoginHooks; // Added use statement
use WP_User;

class SimpleJWTLoginSession
{
    const COOKIE_NAME = 'jwt_token';

    /**
     * Initialize WordPress session hooks
     *
     * @return void
     */
    public static function init()
    {
        // Hook for when a user logs in
        add_action('wp_login', [self::class, 'setJwtCookieOnLogin'], 10, 2);

        // Hook for when a user logs out
        add_action('wp_logout', [self::class, 'clearJwtCookieOnLogout']);
    }

    /**
     * Get root domain from current domain
     *
     * @return string
     */
    private static function getRootDomain()
    {
        $currentDomain = $_SERVER['HTTP_HOST'] ?? COOKIE_DOMAIN;

        // If it's an IP address or localhost, return as is
        if (filter_var($currentDomain, FILTER_VALIDATE_IP) || $currentDomain === 'localhost') {
            return $currentDomain;
        }

        // Extract the main domain (example: from sub.domain.com to domain.com)
        $parts = explode('.', $currentDomain);
        $count = count($parts);

        // Handle special cases with country-specific TLDs (e.g., .co.uk, .com.au)
        $rootDomain = $currentDomain;
        if ($count > 2) {
            // Check for country-specific second-level domains
            $specialTlds = ['co.uk', 'com.au', 'co.nz', 'org.uk', 'net.au', 'org.au', 'ac.uk'];
            $lastTwoParts = $parts[$count - 2] . '.' . $parts[$count - 1];

            if (in_array($lastTwoParts, $specialTlds)) {
                // For special TLDs use the third level domain (example.co.uk)
                if ($count > 3) {
                    $rootDomain = $parts[$count - 3] . '.' . $parts[$count - 2] . '.' . $parts[$count - 1];
                }
            } else {
                // Standard TLD, use second level domain (example.com)
                $rootDomain = $parts[$count - 2] . '.' . $parts[$count - 1];
            }
        }

        return '.' . $rootDomain; // Add a dot prefix to include all subdomains
    }

    /**
     * Set JWT token in cookie when a user logs in through WordPress
     *
     * @param string $username Username
     * @param WP_User $user WP_User object
     * @return void
     */
    public static function setJwtCookieOnLogin($username, $user)
    {
        if (!$user instanceof WP_User) {
            return;
        }

        // Get plugin settings
        // Assuming WordPressData and SimpleJWTLoginSettings are correctly autoloaded or in the current namespace
        $wordPressData = new WordPressData();
        $jwtSettings = new SimpleJWTLoginSettings($wordPressData);

        // Only proceed if authentication is enabled
        if (!$jwtSettings->getAuthenticationSettings()->isAuthenticationEnabled()) {
            return;
        }

        // Generate payload for the token
        $payload = [];
        $payload = AuthenticateService::generatePayload(
            $payload,
            $wordPressData,
            $jwtSettings,
            $user
        );

        // If hooks are enabled, trigger the filter
        // This allows other integrations to modify the payload before we set the final expiration
        if ($jwtSettings->getHooksSettings()->isHookEnable(SimpleJWTLoginHooks::JWT_PAYLOAD_ACTION_NAME)) {
            $payload = $wordPressData->triggerFilter(
                SimpleJWTLoginHooks::JWT_PAYLOAD_ACTION_NAME,
                $payload,
                [] // Original context for the filter
            );
        }

        // --- Start: Get expiration from WordPress session data ---
        $wp_session_expiration_timestamp = null;
        $remember = false; // Default to non-persistent

        // 1. Try to get expiration from user meta (for "Remember Me" logins)
        // This meta key stores the expiration timestamp for persistent logins.
        $token_expires = get_user_meta( $user->ID, 'wp_login_token_expires', true );
        if ( $token_expires && is_numeric( $token_expires ) ) {
            $wp_session_expiration_timestamp = (int) $token_expires;
            $remember = true; // If user meta exists, it's a "remember me" login
            // error_log( 'SimpleJWTLogin: Got expiration from user meta.' ); // Log success
        } else {
            // error_log( 'SimpleJWTLogin: User meta wp_login_token_expires not found or invalid. Trying cookie.' ); // Log fallback

            // 2. If user meta not found, try to get expiration from the logged-in cookie
            // This cookie should be set by WordPress by the time this hook runs.
            $logged_in_cookie_name = '';
            // Ensure WordPress cookie constants are defined
            if ( ! defined( 'LOGGED_IN_COOKIE' ) ) {
                 wp_cookie_constants();
            }

            if ( defined( 'LOGGED_IN_COOKIE' ) && isset( $_COOKIE[ LOGGED_IN_COOKIE ] ) ) {
                $logged_in_cookie_name = LOGGED_IN_COOKIE;
                $cookie_value = $_COOKIE[ $logged_in_cookie_name ];
                $parts = explode( '|', $cookie_value );

                // The expiration timestamp is the 4th part (index 3)
                if ( isset( $parts[3] ) && is_numeric( $parts[3] ) ) {
                    $wp_session_expiration_timestamp = (int) $parts[3];
                    // We can't reliably determine 'remember' status from this cookie value alone here,
                    // but the timestamp itself reflects the correct duration.
                    // error_log( 'SimpleJWTLogin: Got expiration from WordPress logged-in cookie.' ); // Log success
                } else {
                     // error_log( 'SimpleJWTLogin: Could not parse expiration from WordPress logged-in cookie value.' ); // Log failure
                }
            } else {
                 // error_log( 'SimpleJWTLogin: WordPress logged-in cookie not found in $_COOKIE.' ); // Log failure
            }

            // 3. Fallback: If neither user meta nor cookie worked, assume "Remember Me" duration (14 days)
            // This is the most reliable fallback for frontend logins where other methods fail.
            if ( is_null( $wp_session_expiration_timestamp ) ) {
                 error_log( 'SimpleJWTLogin: Could not read expiration from user meta or cookie. Falling back to 14-day duration.' ); // Log fallback
                 $remember = true; // Assume "Remember Me" for the fallback
                 // Default WordPress session durations: 2 days, or 14 days if "remember me" is checked.
                 $base_duration = $remember ? (14 * DAY_IN_SECONDS) : (2 * DAY_IN_SECONDS);
                 // Apply the filter just in case, though it should have run already for the WP cookie
                 $wp_session_duration_seconds = apply_filters(
                     'auth_cookie_expiration',
                     $base_duration,
                     $user->ID,
                     $remember
                 );
                 $wp_session_expiration_timestamp = time() + $wp_session_duration_seconds;
                 // error_log( 'SimpleJWTLogin: Calculated expiration using 14-day fallback.' ); // Log success
            } else {
                 // If we got the timestamp from the cookie, we still need to determine 'remember' status
                 // for the filter below, although the timestamp itself is the primary source.
                 // We can infer 'remember' status by comparing the timestamp to the default non-remembered duration.
                 $default_non_remember_duration = apply_filters('auth_cookie_expiration', (2 * DAY_IN_SECONDS), $user->ID, false);
                 if ($wp_session_expiration_timestamp > (time() + $default_non_remember_duration + 60)) { // Add a small buffer
                     $remember = true;
                 }
            }
        }
        // --- End: Get expiration from WordPress session data ---


        // Set the JWT 'exp' (expiration time) claim to match the WordPress session expiration
        $payload[AuthenticationSettings::JWT_PAYLOAD_PARAM_EXP] = $wp_session_expiration_timestamp;

        // Ensure 'iat' (issued at) is present if not already.
        // Typically, AuthenticateService or JWT::encode handles 'iat'.
        if (!isset($payload['iat'])) {
            $payload['iat'] = time();
        }

        // Generate the token with the potentially modified payload (including our 'exp' claim)
        $token = JWT::encode(
            $payload,
            JwtKeyFactory::getFactory($jwtSettings)->getPrivateKey(),
            $jwtSettings->getGeneralSettings()->getJWTDecryptAlgorithm()
        );

        // Set the cookie with the token
        $secure = is_ssl();
        $httponly = true; // Corrected: Make the cookie accessible only through HTTP protocol for security
        $domain = self::getRootDomain(); // Use root domain instead of current subdomain
        $path = '/'; // Make cookie available across the entire domain

        setcookie(
            self::COOKIE_NAME,
            $token,
            $wp_session_expiration_timestamp, // Cookie 'expires' attribute now matches JWT 'exp' and WP session
            $path,
            $domain,
            $secure,
            $httponly // Ensure HttpOnly is true
        );
    }

    /**
     * Clear JWT token cookie when a user logs out
     *
     * @return void
     */
    public static function clearJwtCookieOnLogout()
    {
        error_log( 'SimpleJWTLogin: clearJwtCookieOnLogout method called.' ); // Add this line

        // Get the root domain
        $domain = self::getRootDomain();

        // Set the cookie with an expiration in the past to delete it
        setcookie(
            self::COOKIE_NAME,
            '',
            time() - 3600, // Set expiration to the past
            '/', // Make cookie available across the entire domain
            $domain,
            is_ssl(),
            true
        );
    }
}
