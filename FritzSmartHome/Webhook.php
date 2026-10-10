<?php
declare(strict_types=1);

/** HTTPS-only, passkey-protected FRITZ! device web console. */
trait FritzSmartHomeWebhook
{
    private const WEBHOOK_CONTROL = '{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}';
    private const PORTAL_VAULT = '{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}';

    private function webPath(): string
    {
        return '/hook/fritz_smart_' . $this->InstanceID;
    }

    private function webOrigin(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https'
            || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])
            || !in_array($parts['path'] ?? '', ['', '/'], true)) return '';
        return 'https://' . strtolower($parts['host'])
            . ((int)($parts['port'] ?? 443) === 443 ? '' : ':' . $parts['port']);
    }

    private function webVault(): int
    {
        $selected = $this->ReadPropertyInteger('VaultInstanceID');
        $candidates = $selected > 0 ? [$selected] : IPS_GetInstanceListByModuleID(self::PORTAL_VAULT);
        $eligible = [];
        foreach ($candidates as $id) {
            $id = (int)$id;
            if (!IPS_InstanceExists($id)) continue;
            try {
                if (strtoupper((string)IPS_GetInstance($id)['ModuleInfo']['ModuleID']) !== self::PORTAL_VAULT
                    || IPS_GetProperty($id, 'PortalEnabled') !== true
                    || $this->webOrigin((string)IPS_GetProperty($id, 'PortalOrigin')) === '') continue;
                $eligible[] = $id;
            } catch (Throwable $e) { continue; }
        }
        return count($eligible) === 1 ? $eligible[0] : 0;
    }

    public function SetupHook(): void
    {
        $this->SetTimerInterval('HookSetup', 0);
        if (IPS_GetKernelRunlevel() !== 10103) return;
        if (!IPS_SemaphoreEnter('ALPORT.WebhookControl', 1000)) {
            $this->SetTimerInterval('HookSetup', 1500);
            $this->logDebug('WebhookControl busy, retry scheduled.');
            return;
        }
        try {
            $ids = IPS_GetInstanceListByModuleID(self::WEBHOOK_CONTROL);
            if (count($ids) !== 1 || IPS_HasChanges((int)$ids[0])) {
                throw new RuntimeException('WebhookControl unavailable or pending changes.');
            }
            $id = (int)$ids[0];
            $current = json_decode((string)IPS_GetProperty($id, 'Hooks'), true);
            if (!is_array($current) || array_values($current) !== $current) {
                throw new RuntimeException('Invalid webhook registry.');
            }
            $path = $this->webPath();
            $enabled = $this->ReadPropertyBoolean('WebEnabled');
            $next = [];
            $found = false;
            foreach ($current as $entry) {
                if (($entry['Hook'] ?? '') === $path) {
                    if ((int)($entry['TargetID'] ?? 0) !== $this->InstanceID) {
                        throw new RuntimeException('Webhook path already belongs to another object.');
                    }
                    if (!$enabled || $found) continue;
                    $found = true;
                }
                $next[] = $entry;
            }
            if ($enabled && !$found) $next[] = ['Hook' => $path, 'TargetID' => $this->InstanceID];
            if ($next !== $current) {
                IPS_SetProperty($id, 'Hooks', json_encode($next, JSON_THROW_ON_ERROR));
                IPS_ApplyChanges($id);
            }
            $this->SetValue('WebPath', $enabled ? $path : 'Web page disabled');
            $this->logDebug('FRITZ! page webhook ' . ($enabled ? 'enabled' : 'disabled') . ': ' . $path);
        } catch (Throwable $e) {
            $this->SetValue('WebPath', 'Webhook setup failed: ' . $e->getMessage());
            $this->SetTimerInterval('HookSetup', 3000);
            $this->logDebug('Webhook setup failed: ' . $e->getMessage());
        } finally {
            IPS_SemaphoreLeave('ALPORT.WebhookControl');
        }
    }

    private function webCSRF(int $vault, int $slot): string
    {
        $cookie = (string)($_COOKIE['SEC_PORTAL_V2_' . $vault] ?? '');
        if ($cookie === '' || strlen($cookie) > 1024) throw new RuntimeException('Portal session cookie missing.');
        return $slot . ':' . hash_hmac('sha256',
            $this->webPath() . '|' . $vault . '|' . $cookie . '|' . $slot,
            $this->ReadAttributeString('WebCSRFKey'));
    }

    private function webValidPOST(array $server, int $vault): bool
    {
        $expected = $this->webOrigin('https://' . ($server['HTTP_HOST'] ?? ''));
        if ($expected === '' || $expected !== $this->webOrigin((string)IPS_GetProperty($vault, 'PortalOrigin'))
            || $this->webOrigin((string)($server['HTTP_ORIGIN'] ?? '')) !== $expected
            || ($server['HTTP_SEC_FETCH_SITE'] ?? 'same-origin') !== 'same-origin') return false;
        $token = (string)($server['HTTP_X_FRITZ_CSRF'] ?? '');
        $slot = (int)floor(time() / 3600);
        return $token !== '' && (
            hash_equals($this->webCSRF($vault, $slot), $token)
            || hash_equals($this->webCSRF($vault, $slot - 1), $token));
    }

    private function webInventory(): array
    {
        $c = $this->credentials();
        if ($c === null) throw new RuntimeException('FRITZ!Box credentials unavailable.');
        $sid = $this->login($c);
        if ($sid === null) throw new RuntimeException('FRITZ!Box login failed.');
        $raw = $this->aha($c, $sid, 'getdevicelistinfos');
        $xml = $raw === null ? false : @simplexml_load_string($raw);
        if ($xml === false) throw new RuntimeException('FRITZ!Box discovery failed.');
        $items = [];
        foreach ($xml->device as $device) {
            $ain = trim((string)$device['identifier']);
            if ($ain === '') continue;
            $socket = isset($device->switch);
            $thermostat = isset($device->hkr);
            if (!$socket && !$thermostat) continue;
            $name = trim((string)$device->name) ?: $ain;
            $online = (string)$device->present === '1';
            $item = ['ain' => $ain, 'name' => $name, 'online' => $online,
                'type' => $thermostat ? 'thermostat' : 'socket'];
            if ($thermostat) {
                $h = $device->hkr;
                foreach (['tist'=>'actual','tsoll'=>'target','komfort'=>'comfort','absenk'=>'economy'] as $field=>$key) {
                    $rawValue = trim((string)$h->{$field});
                    $value = is_numeric($rawValue) ? (int)$rawValue : -1;
                    $item[$key] = $value >= 16 && $value <= 56 ? $value / 2 : null;
                }
                $tsoll = (int)$h->tsoll;
                $item['mode'] = $tsoll === 253 ? 'off' : ($tsoll === 254 ? 'max' : 'setpoint');
                $item['battery'] = is_numeric((string)$h->battery) ? (int)$h->battery : null;
                $item['batteryLow'] = (string)$h->batterylow === '1';
                $item['windowOpen'] = (string)$h->windowopenactiv === '1';
            } else {
                $state = (string)$device->switch->state;
                $item['switch'] = in_array($state, ['0','1'], true) ? $state === '1' : null;
                $item['powerW'] = isset($device->powermeter->power) && is_numeric((string)$device->powermeter->power)
                    ? round((float)$device->powermeter->power / 1000, 2) : null;
                $item['energyKWh'] = isset($device->powermeter->energy) && is_numeric((string)$device->powermeter->energy)
                    ? round((float)$device->powermeter->energy / 1000, 3) : null;
                $item['temperature'] = isset($device->temperature->celsius) && is_numeric((string)$device->temperature->celsius)
                    ? (float)$device->temperature->celsius / 10 : null;
            }
            $items[] = $item;
        }
        usort($items, static function(array $a, array $b): int { return strnatcasecmp($a['name'], $b['name']); });
        return ['credentials'=>$c,'sid'=>$sid,'devices'=>$items];
    }

    private function webBulkCommand(array $payload): array
    {
        if (array_diff(array_keys($payload), ['action','value'])
            || !is_int($payload['value'] ?? null) && !is_float($payload['value'] ?? null)) {
            throw new InvalidArgumentException('Invalid bulk setpoint request.');
        }
        $temperature = (float)$payload['value'];
        if (!is_finite($temperature) || $temperature < 8 || $temperature > 28
            || abs($temperature * 2 - round($temperature * 2)) > 0.00001) {
            throw new InvalidArgumentException('Use 8-28 °C in half-degree steps.');
        }
        $result = json_decode($this->SetAllThermostatsTemperature($temperature), true);
        if (!is_array($result)) throw new RuntimeException('Could not read bulk command response.');
        return ['ok'=>($result['status'] ?? '') === 'success' && count($result['failed'] ?? []) === 0 && !isset($result['error']),
            'report'=>$result];
    }

    private function webCommand(array $payload): array
    {
        if (array_diff(array_keys($payload), ['action','ain','value'])
            || !is_string($payload['action'] ?? null)
            || !is_string($payload['ain'] ?? null)) throw new InvalidArgumentException('Invalid command.');
        $ain = trim($payload['ain']);
        if ($ain === '' || strlen($ain) > 80) throw new InvalidArgumentException('Invalid AIN.');
        $state = $this->webInventory();
        $matched = null;
        foreach ($state['devices'] as $device) {
            if (preg_replace('/\\s+/u','',$device['ain']) === preg_replace('/\\s+/u','',$ain)) {
                $matched = $device;
                break;
            }
        }
        if ($matched === null) throw new InvalidArgumentException('Device not found on this FRITZ!Box.');
        if (!$matched['online']) throw new RuntimeException('Device is offline.');
        $action = $payload['action'];
        $value = $payload['value'] ?? null;
        if ($action === 'switch' && $matched['type'] === 'socket' && is_bool($value)) {
            $command = $value ? 'setswitchon' : 'setswitchoff';
            $expected = $value ? '1' : '0';
            $result = $this->aha($state['credentials'], $state['sid'], $command, $matched['ain']);
            if ($result === null) throw new RuntimeException('Switch command failed.');
            $confirmed = false;
            foreach ([0, 250000] as $delay) {
                if ($delay > 0) usleep($delay);
                $readback = $this->aha($state['credentials'], $state['sid'], 'getswitchstate', $matched['ain']);
                if ($readback === $expected) { $confirmed = true; break; }
            }
            if (!$confirmed) {
                // Some AVM devices return "inval" for getswitchstate but are
                // present in the full AHA device list. Verify that fallback.
                $list = $this->aha($state['credentials'], $state['sid'], 'getdevicelistinfos');
                $xml = $list === null ? false : @simplexml_load_string($list);
                if ($xml !== false) {
                    foreach ($xml->device as $dev) {
                        if (preg_replace('/\\s+/u', '', (string)$dev['identifier']) !==
                            preg_replace('/\\s+/u', '', $matched['ain'])) continue;
                        if (trim((string)$dev->switch->state) === $expected) $confirmed = true;
                        break;
                    }
                }
            }
            if (!$confirmed) throw new RuntimeException('Switch state not yet confirmed; refresh status.');
        } elseif (($action === 'setpoint' || $action === 'mode') && $matched['type'] === 'thermostat') {
            if ($action === 'setpoint') {
                if (!is_int($value) && !is_float($value)) throw new InvalidArgumentException('Temperature must be numeric.');
                $t = (float)$value;
                if (!is_finite($t) || $t < 8 || $t > 28 || abs($t * 2 - round($t * 2)) > 0.00001) {
                    throw new InvalidArgumentException('Use 8-28 °C in half-degree steps.');
                }
                $encoded = (int)round($t * 2);
            } else {
                if (!is_string($value) || !in_array($value, ['off','max','comfort'], true)) {
                    throw new InvalidArgumentException('Unsupported heating mode.');
                }
                $encoded = $value === 'off' ? 253 : ($value === 'max' ? 254 :
                    (isset($matched['comfort']) && $matched['comfort'] !== null
                        ? (int)round($matched['comfort'] * 2) : -1));
                if ($encoded < 0) throw new InvalidArgumentException('Comfort temperature unavailable.');
            }
            $result = $this->aha($state['credentials'], $state['sid'], 'sethkrtsoll', $matched['ain'], $encoded);
            if ($result === null) throw new RuntimeException('Thermostat command failed.');
            $verified = false;
            foreach ([0,350000,750000] as $delay) {
                if ($delay > 0) usleep($delay);
                $readback = $this->aha($state['credentials'], $state['sid'], 'gethkrtsoll', $matched['ain']);
                if ($readback !== null && is_numeric($readback) && (int)$readback === $encoded) { $verified = true; break; }
            }
            if (!$verified) throw new RuntimeException('Thermostat setpoint not yet confirmed; refresh status.');
        } else {
            throw new InvalidArgumentException('Action is not supported for this device.');
        }
        $this->logDebug('Web command confirmed: ' . $matched['name'] . ' (' . $action . ').');
        return ['ok'=>true,'name'=>$matched['name'],'action'=>$action,'confirmed'=>true];
    }

    protected function ProcessHookData(): void
    {
        $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $body = $method === 'POST' ? (string)file_get_contents('php://input', false, null, 0, 16385) : '';
        $result = $this->webResponse($_SERVER, $_GET, $body);
        http_response_code($result['status']);
        foreach ($result['headers'] as $name=>$value) header($name . ': ' . $value);
        if ($method !== 'HEAD') echo $result['body'];
    }

    private function webResponse(array $server, array $query, string $body): array
    {
        $headers = [
            'Cache-Control'=>'private, no-store, max-age=0','Pragma'=>'no-cache',
            'X-Content-Type-Options'=>'nosniff','Referrer-Policy'=>'no-referrer',
            'X-Frame-Options'=>'DENY','Permissions-Policy'=>'camera=(), microphone=(), geolocation=()',
            'Content-Type'=>'application/json; charset=utf-8',
            'Content-Security-Policy'=>"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        ];
        $reply = static function(int $status, $data, array $extra=[]) use ($headers): array {
            return ['status'=>$status,'headers'=>array_replace($headers,$extra),
                'body'=>is_string($data) ? $data : json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)];
        };
        $method = strtoupper((string)($server['REQUEST_METHOD'] ?? 'GET'));
        if (!in_array($method, ['GET','HEAD','POST'], true)) return $reply(405, ['error'=>'Method not allowed'], ['Allow'=>'GET, HEAD, POST']);
        if (!$this->ReadPropertyBoolean('WebEnabled')) return $reply(503, ['error'=>'FRITZ! control page disabled.']);
        $vault = $this->webVault();
        if (!$vault || !function_exists('SEC_IsPortalAuthenticated')) return $reply(503, ['error'=>'A valid SecretsManager HTTPS portal is required.']);
        try {
            if (SEC_IsPortalAuthenticated($vault) !== true) {
                if ($method === 'GET' && !isset($query['view'])) {
                    return $reply(303, '', ['Location'=>'/hook/secrets_'.$vault.'?portal=1&return='.rawurlencode($this->webPath())]);
                }
                return $reply(401, ['error'=>'Passkey session required. Sign in again.']);
            }
            $expected = $this->webOrigin((string)IPS_GetProperty($vault, 'PortalOrigin'));
            if ($expected === '' || $this->webOrigin('https://' . ($server['HTTP_HOST'] ?? '')) !== $expected) {
                return $reply(403, ['error'=>'Open this page through the SecretsManager HTTPS portal origin.']);
            }
            if ($method === 'POST') {
                if (!$this->webValidPOST($server, $vault)) return $reply(403, ['error'=>'Invalid session-bound security token or origin.']);
                if (strlen($body) > 16384) return $reply(413, ['error'=>'Request too large.']);
                if (strtolower(trim(explode(';',(string)($server['CONTENT_TYPE'] ?? ''),2)[0])) !== 'application/json') {
                    return $reply(415, ['error'=>'JSON body required.']);
                }
                $data = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
                if (!is_array($data)) throw new InvalidArgumentException('Invalid JSON body.');
                if (($data['action'] ?? null) === 'bulk_setpoint') {
                    return $reply(200, $this->webBulkCommand($data));
                }
                return $reply(200, $this->webCommand($data));
            }
            if (($query['view'] ?? '') === 'state') {
                $snapshot = $this->webInventory();
                return $reply(200, ['instanceID'=>$this->InstanceID,'updated'=>date('c'),'devices'=>$snapshot['devices']]);
            }
            if (isset($query['view'])) return $reply(404, ['error'=>'Unknown view.']);
            $nonce = base64_encode(random_bytes(24));
            $escape = static function($value): string { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); };
            $template = file_get_contents(__DIR__ . '/page.html');
            if ($template === false) throw new RuntimeException('Page template not found.');
            $html = strtr($template, [
                '{{NONCE}}'=>$escape($nonce),
                '{{PATH}}'=>$escape($this->webPath()),
                '{{CSRF}}'=>$escape($this->webCSRF($vault, (int)floor(time()/3600))),
                '{{INSTANCE}}'=>(string)$this->InstanceID
            ]);
            return $reply(200, $html, [
                'Content-Type'=>'text/html; charset=utf-8',
                'Content-Security-Policy'=>"default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; connect-src 'self'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            ]);
        } catch (JsonException | InvalidArgumentException $e) {
            return $reply(422, ['error'=>$e->getMessage()]);
        } catch (Throwable $e) {
            $this->logDebug('FRITZ! web request failed: ' . $e->getMessage());
            return $reply(503, ['error'=>'Request failed. Check the module Last Error / Debug variables or refresh the page.']);
        }
    }
}
