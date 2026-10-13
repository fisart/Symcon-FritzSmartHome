<?php
declare(strict_types=1);

// Isolated AVM AHA XML fixtures: no FRITZ!Box network or Symcon installation required.
if (!class_exists('SimpleXMLElement')) {
    fwrite(STDERR, "SimpleXML extension is required for this test.\n");
    exit(1);
}
class IPSModule {}
require_once __DIR__ . '/../FritzSmartHome/module.php';

$module = new FritzSmartHome();
$method = new ReflectionMethod(FritzSmartHome::class, 'batteryReading');
$examples = [
    [
        'name' => 'Device-level 100 overrides stale nested value',
        'xml' => '<device><battery>100</battery><batterylow>0</batterylow><hkr><battery>0</battery><batterylow>1</batterylow></hkr></device>',
        'want' => ['percent' => 100, 'source' => 'device', 'low' => false],
    ],
    [
        'name' => 'Older HKR-only devices still work',
        'xml' => '<device><hkr><battery>72</battery><batterylow>1</batterylow></hkr></device>',
        'want' => ['percent' => 72, 'source' => 'hkr', 'low' => true],
    ],
    [
        'name' => 'True zero percent remains valid',
        'xml' => '<device><battery>0</battery><hkr /></device>',
        'want' => ['percent' => 0, 'source' => 'device', 'low' => null],
    ],
    [
        'name' => 'Missing battery is unknown',
        'xml' => '<device><hkr /></device>',
        'want' => ['percent' => null, 'source' => null, 'low' => null],
    ],
    [
        'name' => 'Invalid top-level battery falls back to HKR',
        'xml' => '<device><battery>255</battery><batterylow>bad</batterylow><hkr><battery>100</battery><batterylow>0</batterylow></hkr></device>',
        'want' => ['percent' => 100, 'source' => 'hkr', 'low' => false],
    ],
    [
        'name' => 'Empty top-level battery is not converted to zero',
        'xml' => '<device><battery></battery><hkr><battery>99</battery></hkr></device>',
        'want' => ['percent' => 99, 'source' => 'hkr', 'low' => null],
    ],
];
foreach ($examples as $example) {
    $actual = $method->invoke($module, new SimpleXMLElement($example['xml']));
    if ($actual !== $example['want']) {
        fwrite(STDERR, $example['name'] . ': wrong result ' . var_export($actual, true) . "\n");
        exit(1);
    }
    echo 'PASS: ' . $example['name'] . "\n";
}
echo "Battery parsing fixtures passed.\n";
