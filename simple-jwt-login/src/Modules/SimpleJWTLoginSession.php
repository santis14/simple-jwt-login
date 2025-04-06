<?php

namespace SimpleJWTLogin\Modules;

use SimpleJWTLogin\Helpers\Jwt\JwtKeyFactory;
use SimpleJWTLogin\Libraries\JWT\JWT;
use SimpleJWTLogin\Modules\Settings\AuthenticationSettings;
use SimpleJWTLogin\Services\AuthenticateService;
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
        if ($jwtSettings->getHooksSettings()->isHookEnable(SimpleJWTLoginHooks::JWT_PAYLOAD_ACTION_NAME)) {
            $payload = $wordPressData->triggerFilter(
                SimpleJWTLoginHooks::JWT_PAYLOAD_ACTION_NAME,
                $payload,
                []
            );
        }
        
        // Generate the token
        $token = JWT::encode(
            $payload,
            JwtKeyFactory::getFactory($jwtSettings)->getPrivateKey(),
            $jwtSettings->getGeneralSettings()->getJWTDecryptAlgorithm()
        );
        
        // Set the cookie with the token
        // The cookie expiration matches the JWT expiration if present, otherwise uses WordPress session
        $expiration = isset($payload[AuthenticationSettings::JWT_PAYLOAD_PARAM_EXP]) 
            ? $payload[AuthenticationSettings::JWT_PAYLOAD_PARAM_EXP]
            : 0; // 0 means it will be a session cookie (expires when browser closes)
        
        $secure = is_ssl();
        $httponly = true; // Make the cookie accessible only through HTTP protocol
        $domain = self::getRootDomain(); // Use root domain instead of current subdomain
        
        setcookie(
            self::COOKIE_NAME,
            $token,
            $expiration,
            '/', // Make cookie available across the entire domain
            $domain,
            $secure,
            false
        );
    }
    
    /**
     * Clear JWT token cookie when a user logs out
     * 
     * @return void
     */
    public static function clearJwtCookieOnLogout()
    {
        // Get the root domain
        $domain = self::getRootDomain();
        
        // Set the cookie with an expiration in the past to delete it
        setcookie(
            self::COOKIE_NAME,
            '',
            time() - 3600,
            '/', // Make cookie available across the entire domain
            $domain,
            is_ssl(),
            true
        );
    }
}
