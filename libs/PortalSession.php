<?php
declare(strict_types=1);

// This helper is bundled with independently installed Symcon libraries.
if (!class_exists('AFPortalSessionV1', false)) {
    final class AFPortalSessionV1
    {
        /** Call only after SEC_IsPortalAuthenticated has approved this request. */
        public static function authenticatedCookie(int $vault): string
        {
            if (!function_exists('SEC_GetReplacementInfo')) {
                $cookie = $_COOKIE['SEC_PORTAL_V2_' . $vault] ?? '';
                if (!is_string($cookie) || $cookie === '' || strlen($cookie) > 1024) {
                    throw new RuntimeException('Portal session cookie missing.');
                }
                return $cookie;
            }

            // Use the backend pinned by this migration adapter, even if other vaults have cookies.
            $info = json_decode(SEC_GetReplacementInfo($vault), true, 32, JSON_THROW_ON_ERROR);
            $backend = $info['backend'] ?? null;
            if (($info['engine'] ?? null) !== 'native-only' || ($info['ready'] ?? false) !== true
                || !is_int($backend) || $backend <= 0) {
                throw new RuntimeException('Native portal backend binding unavailable.');
            }
            $pattern = '/(?:^|;\s*)__Host-SECB_' . $backend . '=([A-Za-z0-9_-]{43})(?=;|$)/';
            if (preg_match_all($pattern, (string)($_SERVER['HTTP_COOKIE'] ?? ''), $matches) !== 1) {
                throw new RuntimeException('Native portal session cookie missing or ambiguous.');
            }
            return $matches[1][0];
        }
    }
}
