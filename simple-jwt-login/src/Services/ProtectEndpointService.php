<?php

namespace SimpleJWTLogin\Services;

use Exception;
use SimpleJWTLogin\ErrorCodes;
use SimpleJWTLogin\Modules\Settings\ProtectEndpointSettings;

class ProtectEndpointService extends BaseService
{
    /**
     * @var RouteService $routeService
     */
    private $routeService;

    /**
     * @param RouteService $routeService
     *
     * @return $this
     */
    public function withRouteService($routeService)
    {
        $this->routeService = $routeService;

        return $this;
    }

    /**
     * @param string $currentUrl
     * @param string $documentRoot
     *
     * @throws Exception
     * @return bool
     */
    public function hasAccess($currentUrl, $documentRoot)
    {
        // --- DEBUG LOGGING START ---
        $requestUri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'NOT SET';
        $isLoggedIn = $this->wordPressData->isUserLoggedIn() ? 'YES' : 'NO';
        $settingsEnabled = $this->jwtSettings->getProtectEndpointsSettings()->isEnabled() ? 'YES' : 'NO';
        error_log(
            "[SimpleJWTLogin Debug] Checking access | Request URI: " . $requestUri
            . " | currentUrl: " . $currentUrl
            . " | WP Logged In: " . $isLoggedIn
            . " | Protect Enabled: " . $settingsEnabled
        );
        // --- DEBUG LOGGING END ---


        // SUPERSEDING CHECK: Immediately allow any request targeting admin-ajax.php
        if (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/wp-admin/admin-ajax.php') === 0) {
            // --- DEBUG LOGGING ---
            error_log("[SimpleJWTLogin Debug] Allowing access: SERVER_URI check matched admin-ajax.php for: " . $requestUri);
            // --- DEBUG LOGGING END ---
            return true;
        }

        // Original checks follow...
        if ($this->jwtSettings->getProtectEndpointsSettings()->isEnabled() === false) {
             // --- DEBUG LOGGING ---
             error_log("[SimpleJWTLogin Debug] Allowing access: Protection disabled.");
             // --- DEBUG LOGGING END ---
            return true;
        }

        if ($this->wordPressData->isUserLoggedIn()) {
             // --- DEBUG LOGGING ---
             error_log("[SimpleJWTLogin Debug] Allowing access: User is logged in via WordPress.");
             // --- DEBUG LOGGING END ---
            return true;
        }

        $parsed = parse_url($currentUrl);

        if (isset($parsed['path']) && strpos($parsed['path'], '/wp-admin/admin-ajax.php') === 0) {
             // --- DEBUG LOGGING ---
             error_log("[SimpleJWTLogin Debug] Allowing access: Parsed path check matched admin-ajax.php for: " . $parsed['path']);
             // --- DEBUG LOGGING END ---
            return true;
        }


        $pathFromAbs = isset($parsed['path']) ? rtrim(str_replace($documentRoot, '', ABSPATH), '/') : 'N/A';
        $path = isset($parsed['path']) ? str_replace($pathFromAbs . '/wp-json', '', $parsed['path']) : 'N/A';
        $restRoute = !empty($this->request['rest_route']) ? $this->request['rest_route'] : 'N/A';

         // --- DEBUG LOGGING ---
         error_log("[SimpleJWTLogin Debug] Paths for isEndpointProtected check | path: " . $path . " | rest_route: " . $restRoute);
         // --- DEBUG LOGGING END ---

        $isEndpointsProtected = true;
        if (!empty(trim($path, '/')) && $path !== 'N/A') {
            $isEndpointsProtected = $this->isEndpointProtected($path);
             // --- DEBUG LOGGING ---
             error_log("[SimpleJWTLogin Debug] isEndpointProtected check result (path): " . ($isEndpointsProtected ? 'Protected' : 'Not Protected'));
             // --- DEBUG LOGGING END ---
        }
        // Important: Check if the first check already determined it's protected before overwriting with the second check
        if ($isEndpointsProtected && !empty($this->request['rest_route'])) {
            $isEndpointsProtected = $this->isEndpointProtected($this->request['rest_route']);
             // --- DEBUG LOGGING ---
             error_log("[SimpleJWTLogin Debug] isEndpointProtected check result (rest_route): " . ($isEndpointsProtected ? 'Protected' : 'Not Protected'));
             // --- DEBUG LOGGING END ---
        }

        if ($isEndpointsProtected === false) {
             // --- DEBUG LOGGING ---
             error_log("[SimpleJWTLogin Debug] Allowing access: Endpoint determined as NOT protected.");
             // --- DEBUG LOGGING END ---
            return true;
        }

         // --- DEBUG LOGGING ---
         error_log("[SimpleJWTLogin Debug] Endpoint determined as PROTECTED. Proceeding with JWT check for URI: " . $requestUri);
         // --- DEBUG LOGGING END ---

        try {
            $jwt = $this->getJwtFromRequestHeaderOrCookie();
            if (empty($jwt)) {
                // --- DEBUG LOGGING ---
                error_log("[SimpleJWTLogin Debug] Denying access: JWT is missing for protected endpoint: " . $requestUri);
                // --- DEBUG LOGGING END ---
                throw new Exception('JWT is not present and we can not search for a user.', ErrorCodes::ERR_PROTECT_ENDPOINTS_MISSING_JWT);
            }

            $user = $this->routeService->getUserFromJwt($jwt);
            $this->validateJwtRevoked(
                $this->wordPressData->getUserProperty($user, 'ID'),
                $jwt
            );
           
            
            if ($this->routeService->wordPressData->isUserLoggedIn()) {
                return true;
            }
            $this->routeService->wordPressData->loginUser($user);

            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * @param string $endpoint
     * @return bool
     */
    private function isEndpointProtected($endpoint)
    {
        // --- DEBUG LOGGING ---
        error_log("[SimpleJWTLogin Debug] Inside isEndpointProtected for endpoint: " . $endpoint);
        // --- DEBUG LOGGING END ---

        if (strpos($endpoint, '/') !== 0) {
            $endpoint = '/' . $endpoint;
        }

        // Explicitly skip admin-ajax.php requests
        if (strpos($endpoint, '/wp-admin/admin-ajax.php') === 0) {
             // --- DEBUG LOGGING ---
             error_log("[SimpleJWTLogin Debug] isEndpointProtected returning false (admin-ajax check)");
             // --- DEBUG LOGGING END ---
            return false;
        }

        $action = $this->jwtSettings->getProtectEndpointsSettings()->getAction();
        $skipNamespace = '/' . trim(
            $this->jwtSettings->getGeneralSettings()->getRouteNamespace(),
            '/'
        );
        $endpoint = $this->removeLastSlash($endpoint);
        $adminPath = trim(
            str_replace($this->wordPressData->getSiteUrl(), '', $this->wordPressData->getAdminUrl()),
            '/'
        );
        if (strpos($endpoint, $skipNamespace) === 0
            || strpos(trim($endpoint, '/'), $adminPath) === 0) {
            //Skip simple jwt login endpoints and wp-admin
            return false;
        }

        $protectSettings = $this->jwtSettings->getProtectEndpointsSettings();
        switch ($action) {
            case ProtectEndpointSettings::ALL_ENDPOINTS:
                return $this->parseDomainsAndGetResult(
                    $endpoint,
                    $protectSettings->getWhitelistedDomains(),
                    true,
                    false
                );
            case ProtectEndpointSettings::SPECIFIC_ENDPOINTS:
                return $this->parseDomainsAndGetResult(
                    $endpoint,
                    $protectSettings->getProtectedEndpoints(),
                    false,
                    true
                );
        }

        return true;
    }

    /**
     * @param string $endpoint
     * @param array $domains
     * @param bool $defaultValue
     * @param bool $setValue
     * @return bool
     */
    private function parseDomainsAndGetResult($endpoint, $domains, $defaultValue, $setValue)
    {
        $isEndpointProtected = $defaultValue;
        foreach ($domains as $protectedEndpoint) {
            $protectedURL = $this->removeWpJsonFromEndpoint($protectedEndpoint['url']);
            $endpoint = $this->removeWpJsonFromEndpoint($endpoint);
            if (empty(trim($protectedURL, '/'))) {
                continue;
            }
            // By default, start_with match
            $match = strpos(strtolower($endpoint), strtolower($protectedURL)) === 0;

            if ($protectedEndpoint['match']  === ProtectEndpointSettings::ENDPOINT_MATCH_EXACT) {
                $match = strtolower($endpoint) == strtolower($protectedURL);
            }

            if (!$match) {
                continue;
            }
           
            switch ($protectedEndpoint['method']) {
                case ProtectEndpointSettings::REQUEST_METHOD_ALL:
                    $isEndpointProtected = $setValue; // Same as before.
                    break;
                default:
                    if ($protectedEndpoint['method'] === $this->requestMetod) {
                        $isEndpointProtected = $setValue;
                    }
                    break;
            }
        }

        return $isEndpointProtected;
    }

    /**
     * @param string $endpoint
     * @return string
     */
    private function removeWpJsonFromEndpoint($endpoint)
    {
        $endpoint = str_replace('/wp-json', '', $endpoint);

        return $this->removeLastSlash($endpoint);
    }

    /**
     * @param string $endpoint
     * @return string
     */
    private function addFirstSlash($endpoint)
    {
        if (strpos($endpoint, '/') !== 0) {
            return '/' . $endpoint;
        }

        return $endpoint;
    }

    /**
     * @param string $endpoints
     * @return string
     */
    private function removeLastSlash($endpoints)
    {
        return $this->addFirstSlash(rtrim($endpoints, '/'));
    }
}
