<?php
declare(strict_types=1);
require __DIR__ . '/../libs/PortalSession.php';

function assertSession(bool $condition, string $reason): void
{
    if (!$condition) throw new RuntimeException($reason);
}

function expectSessionRefusal(int $vault): void
{
    try {
        AFPortalSessionV1::authenticatedCookie($vault);
    } catch (RuntimeException $error) {
        return;
    }
    throw new RuntimeException('Unexpected portal session cookie acceptance.');
}

$_COOKIE = ['SEC_PORTAL_V2_7' => 'legacy-session'];
assertSession(AFPortalSessionV1::authenticatedCookie(7) === 'legacy-session', 'Legacy session lost.');
expectSessionRefusal(8);

if (!function_exists('SEC_GetReplacementInfo')) {
    function SEC_GetReplacementInfo(int $vault): string
    {
        return json_encode(['engine' => 'native-only', 'ready' => $vault === 7, 'backend' => 18], JSON_THROW_ON_ERROR);
    }
}
$session = str_repeat('A', 43);
$cookie = '__Host-SECB_18=' . $session;
$other = '__Host-SECB_19=' . str_repeat('B', 43);
$_SERVER['HTTP_COOKIE'] = $other . '; ' . $cookie;
assertSession(AFPortalSessionV1::authenticatedCookie(7) === $session, 'Native session must use the pinned backend.');
expectSessionRefusal(8);
$_SERVER['HTTP_COOKIE'] = $other;
expectSessionRefusal(7); // Includes a stale legacy cookie, which cannot substitute for the native session.
$_SERVER['HTTP_COOKIE'] = $cookie . '; ' . $cookie;
expectSessionRefusal(7);
$_SERVER['HTTP_COOKIE'] = '__Host-SECB_18=' . str_repeat('C', 43);
assertSession(AFPortalSessionV1::authenticatedCookie(7) !== $session, 'Session binding must change when the cookie rotates.');
echo "Portal session compatibility passed.\n";
