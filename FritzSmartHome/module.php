<?php
declare(strict_types=1);

class FritzSmartHome extends IPSModule
{
    public function Create(): void
    {
        parent::Create();
        $this->RegisterPropertyInteger('SecretsManagerID', 47118);
        $this->RegisterPropertyString('SecretKey', 'FB-DSL');
        $this->RegisterPropertyInteger('PollSeconds', 60);
        $this->RegisterPropertyBoolean('Enabled', true);
        $this->RegisterPropertyBoolean('DebugEnabled', false);
        $this->RegisterTimer('Poll', 60000, 'FSH_Poll($_IPS["TARGET"]);');
        $this->RegisterVariableString('LastError', 'Last Error', '', 998);
        $this->RegisterVariableString('Debug', 'Debug', '', 999);
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        $this->SetTimerInterval('Poll', $this->ReadPropertyBoolean('Enabled')
            ? max(15, $this->ReadPropertyInteger('PollSeconds')) * 1000 : 0);
    }

    public function GetConfigurationForm(): string
    {
        return json_encode([
            'elements' => [
                ['type'=>'NumberSpinner','name'=>'SecretsManagerID','caption'=>'SecretsManager Instance ID'],
                ['type'=>'ValidationTextBox','name'=>'SecretKey','caption'=>'SecretsManager Key'],
                ['type'=>'NumberSpinner','name'=>'PollSeconds','caption'=>'Polling (seconds)'],
                ['type'=>'CheckBox','name'=>'Enabled','caption'=>'Enabled'],
                ['type'=>'CheckBox','name'=>'DebugEnabled','caption'=>'Debug']
            ],
            'actions' => [
                ['type'=>'Button','caption'=>'Discover now','onClick'=>'FSH_Poll($id);']
            ]
        ], JSON_UNESCAPED_SLASHES);
    }

    private function logDebug(string $message): void
    {
        if ($this->ReadPropertyBoolean('DebugEnabled')) {
            $this->SetValue('Debug', substr(date('Y-m-d H:i:s').' '.$message."\n".$this->GetValue('Debug'), 0, 16000));
        }
    }

    private function error(string $message): void
    {
        $this->SetValue('LastError', $message);
        $this->SetStatus(200);
        $this->logDebug($message);
    }

    private function credentials(): ?array
    {
        if (!function_exists('SEC_GetSecret')) {
            $this->error('SEC_GetSecret unavailable');
            return null;
        }
        try {
            $raw = SEC_GetSecret($this->ReadPropertyInteger('SecretsManagerID'), $this->ReadPropertyString('SecretKey'));
            $data = is_array($raw) ? $raw : json_decode((string)$raw, true);
        } catch (Throwable $e) {
            $this->error('SecretsManager lookup failed');
            return null;
        }
        if (!is_array($data) || empty($data['IP']) || empty($data['User']) || empty($data['PW'])) {
            $this->error('Secret must provide IP, User and PW');
            return null;
        }
        $host = trim((string)$data['IP']);
        if (!preg_match('~^https?://~i', $host)) $host = 'http://'.$host;
        if (!filter_var($host, FILTER_VALIDATE_URL)) {
            $this->error('Invalid FRITZ!Box host');
            return null;
        }
        return ['host'=>rtrim($host, '/'), 'user'=>(string)$data['User'], 'pass'=>(string)$data['PW']];
    }

    private function http(string $url, ?array $post = null): ?string
    {
        $ch = curl_init($url);
        if ($ch === false) return null;
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER=>true, CURLOPT_CONNECTTIMEOUT=>5,
            CURLOPT_TIMEOUT=>12, CURLOPT_FOLLOWLOCATION=>false,
            CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_SSL_VERIFYHOST=>2
        ]);
        if ($post !== null) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
        }
        $result = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if (!is_string($result) || $status !== 200) {
            $this->logDebug('HTTP failure, code '.$status);
            return null;
        }
        return trim($result);
    }

    private function login(array $c): ?string
    {
        $url = $c['host'].'/login_sid.lua';
        $first = $this->http($url);
        $xml = $first === null ? false : @simplexml_load_string($first);
        if ($xml === false) { $this->error('Login challenge unavailable'); return null; }
        $sid = (string)$xml->SID;
        if (preg_match('/^[a-f0-9]{16}$/i', $sid) && $sid !== '0000000000000000') return $sid;
        if ((int)$xml->BlockTime > 0) { $this->error('FRITZ!Box login blocked'); return null; }
        $challenge = (string)$xml->Challenge;
        if (str_starts_with($challenge, '2$')) {
            $p = explode('$', $challenge);
            if (count($p) !== 5 || !ctype_digit($p[1]) || !ctype_digit($p[3])) {
                $this->error('Invalid PBKDF2 challenge'); return null;
            }
            $h1 = hash_pbkdf2('sha256', $c['pass'], hex2bin($p[2]), (int)$p[1], 32, true);
            $h2 = hash_pbkdf2('sha256', $h1, hex2bin($p[4]), (int)$p[3], 32, true);
            $response = $p[4].'$'.bin2hex($h2);
        } else {
            if ($challenge === '') { $this->error('Missing challenge'); return null; }
            $bytes = iconv('UTF-8', 'UTF-16LE', $challenge.'-'.$c['pass']);
            if ($bytes === false) { $this->error('Login encoding error'); return null; }
            $response = $challenge.'-'.md5($bytes);
        }
        $answer = $this->http($url, ['username'=>$c['user'], 'response'=>$response]);
        $xml = $answer === null ? false : @simplexml_load_string($answer);
        $sid = $xml === false ? '' : (string)$xml->SID;
        if (!preg_match('/^[a-f0-9]{16}$/i', $sid) || $sid === '0000000000000000') {
            $this->error('FRITZ!Box authentication failed'); return null;
        }
        return $sid;
    }

    private function aha(array $c, string $sid, string $cmd, string $ain = '', ?int $param = null): ?string
    {
        $q = ['sid'=>$sid,'switchcmd'=>$cmd];
        if ($ain !== '') $q['ain'] = preg_replace('/\\s+/u', '', $ain);
        if ($param !== null) $q['param'] = $param;
        $r = $this->http($c['host'].'/webservices/homeautoswitch.lua?'.http_build_query($q));
        if ($r === 'inval') {
            $this->logDebug('AHA inval: '.$cmd.' AIN '.$ain);
            return null;
        }
        return $r;
    }

    private function vid(string $ain, string $suffix): string
    {
        return 'D'.substr(sha1($ain), 0, 12).'_'.$suffix;
    }

    // One stable Dummy instance per AVM AIN; device renames never alter identities.
    private function deviceParent(string $ain, string $name): int
    {
        $ident = 'Device_' . substr(sha1($ain), 0, 16);
        $dummy = @IPS_GetObjectIDByIdent($ident, $this->InstanceID);
        if ($dummy === false) {
            $dummy = IPS_CreateInstance('{485D0419-BE97-4548-AA9C-C083EB82E61E}');
            IPS_SetParent($dummy, $this->InstanceID);
            IPS_SetIdent($dummy, $ident);
            IPS_ApplyChanges($dummy);
            $this->logDebug('Created device Dummy instance for ' . $name);
        }
        if (IPS_GetName($dummy) !== $name) {
            IPS_SetName($dummy, $name);
        }
        return $dummy;
    }

    // The action script routes button / slider changes back to this module instance.
    private function actionScript(): int
    {
        $ident = 'FritzSmartHomeAction';
        $id = @IPS_GetObjectIDByIdent($ident, $this->InstanceID);
        if ($id === false) {
            $id = IPS_CreateScript(0);
            IPS_SetParent($id, $this->InstanceID);
            IPS_SetIdent($id, $ident);
            IPS_SetName($id, 'FRITZ! Smart Home Action');
            IPS_SetScriptContent($id, '<?php' . "\n" .
                'if (isset($_IPS["VARIABLE"], $_IPS["VALUE"])) {' . "\n" .
                '    $variableID = (int)$_IPS["VARIABLE"];' . "\n" .
                '    $dummyID = IPS_GetParent($variableID);' . "\n" .
                '    $moduleID = IPS_GetParent($dummyID);' . "\n" .
                '    IPS_RequestAction($moduleID, IPS_GetObject($variableID)["ObjectIdent"], $_IPS["VALUE"]);' . "\n" .
                '}' . "\n");
        }
        IPS_SetHidden($id, true);
        return $id;
    }

    private function registerField(string $ain, string $name, string $suffix, string $label, string $type, bool $action = false): void
    {
        $parent = $this->deviceParent($ain, $name);
        $ident = $this->vid($ain, $suffix);
        $variableID = @IPS_GetObjectIDByIdent($ident, $parent);
        if ($variableID === false) {
            // Migrate already-created module-root variables without losing IDs / archives.
            $legacyID = @IPS_GetObjectIDByIdent($ident, $this->InstanceID);
            if ($legacyID !== false && IPS_GetObject($legacyID)['ObjectType'] === 2) {
                IPS_SetParent($legacyID, $parent);
                $variableID = $legacyID;
            } else {
                $typeCode = $type === 'bool' ? 0 : ($type === 'int' ? 1 : 2);
                $variableID = IPS_CreateVariable($typeCode);
                IPS_SetParent($variableID, $parent);
                IPS_SetIdent($variableID, $ident);
            }
        }
        $caption = $label;
        if (IPS_GetName($variableID) !== $caption) {
            IPS_SetName($variableID, $caption);
        }
        if ($type === 'bool') {
            IPS_SetVariableCustomProfile($variableID, '~Switch');
        }
        if ($action) {
            IPS_SetVariableCustomAction($variableID, $this->actionScript());
        }
    }

    private function setField(string $ain, string $suffix, $value): void
    {
        $parent = @IPS_GetObjectIDByIdent('Device_' . substr(sha1($ain), 0, 16), $this->InstanceID);
        if ($parent === false) return;
        $variableID = @IPS_GetObjectIDByIdent($this->vid($ain, $suffix), $parent);
        if ($variableID !== false) SetValue($variableID, $value);
    }

    public function RequestAction($Ident, $Value): void
    {
        if (!preg_match('/^D([a-f0-9]{12})_(Switch|Setpoint|Mode)$/', (string)$Ident, $matches)) {
            throw new InvalidArgumentException('Unsupported action');
        }
        $c = $this->credentials();
        if ($c === null || ($sid = $this->login($c)) === null) return;
        $list = $this->aha($c, $sid, 'getdevicelistinfos');
        $xml = $list === null ? false : @simplexml_load_string($list);
        if ($xml === false) { $this->error('Cannot resolve device AIN'); return; }
        $ain = '';
        foreach ($xml->device as $dev) {
            $candidate = trim((string)$dev['identifier']);
            if (substr(sha1($candidate), 0, 12) === $matches[1]) { $ain = $candidate; break; }
        }
        if ($ain === '') { $this->error('Device no longer discovered'); return; }
        $field = $matches[2];
        if ($field === 'Switch') {
            $cmd = (bool)$Value ? 'setswitchon' : 'setswitchoff';
            $reply = $this->aha($c, $sid, $cmd, $ain);
        } elseif ($field === 'Mode') {
            if (!in_array((int)$Value, [0,1,2], true)) throw new InvalidArgumentException('Invalid mode');
            $param = (int)$Value === 1 ? 253 : ((int)$Value === 2 ? 254 : 0);
            if ($param === 0) {
                $comfort = $this->GetValue($this->vid($ain, 'Comfort'));
                $param = max(16, min(56, (int)round((float)$comfort * 2)));
            }
            $reply = $this->aha($c, $sid, 'sethkrtsoll', $ain, $param);
        } else {
            $temp = (float)$Value;
            if (!is_finite($temp) || $temp < 8 || $temp > 28) throw new InvalidArgumentException('Setpoint must be 8–28°C');
            $reply = $this->aha($c, $sid, 'sethkrtsoll', $ain, (int)round($temp * 2));
        }
        if ($reply === null) { $this->error('Device command failed'); return; }
        $this->Poll();
    }

    public function Poll(): void
    {
        if (!$this->ReadPropertyBoolean('Enabled')) return;
        $c = $this->credentials();
        if ($c === null || ($sid = $this->login($c)) === null) return;
        $list = $this->aha($c, $sid, 'getdevicelistinfos');
        $xml = $list === null ? false : @simplexml_load_string($list);
        if ($xml === false) { $this->error('Discovery XML unavailable'); return; }
        $count = 0;
        foreach ($xml->device as $dev) {
            $ain = trim((string)$dev['identifier']);
            if ($ain === '') continue;
            $socket = isset($dev->switch);
            $thermo = isset($dev->hkr);
            if (!$socket && !$thermo) continue;
            $count++;
            $name = trim((string)$dev->name) ?: $ain;
            $this->registerField($ain,$name,'Online','Online','bool');
            $this->setField($ain,'Online',(string)$dev->present === '1');
            if ($socket) {
                foreach ([
                    ['Switch','Switch','bool',true],['PowerW','Power (W)','float',false],
                    ['EnergyKWh','Energy (kWh)','float',false],['Temperature','Temperature °C','float',false]
                ] as [$s,$n,$t,$a]) $this->registerField($ain,$name,$s,$n,$t,$a);
                $state = trim((string)$dev->switch->state);
                if ($state === '0' || $state === '1') $this->setField($ain,'Switch',$state === '1');
                if (isset($dev->powermeter)) {
                    if (is_numeric((string)$dev->powermeter->power)) $this->setField($ain,'PowerW',(float)$dev->powermeter->power/1000);
                    if (is_numeric((string)$dev->powermeter->energy)) $this->setField($ain,'EnergyKWh',(float)$dev->powermeter->energy/1000);
                }
                if (isset($dev->temperature) && is_numeric((string)$dev->temperature->celsius)) {
                    $this->setField($ain,'Temperature',(float)$dev->temperature->celsius/10);
                }
            }
            if ($thermo) {
                foreach ([
                    ['Actual','Actual °C','float',false], ['Setpoint','Target °C','float',true],
                    ['Comfort','Comfort °C','float',false], ['Economy','Economy °C','float',false],
                    ['Battery','Battery %','int',false], ['BatteryLow','Battery low','bool',false],
                    ['WindowOpen','Window open','bool',false], ['Boost','Boost active','bool',false],
                    ['Mode','Mode (0=normal, 1=off, 2=on)','int',true]
                ] as [$s,$n,$t,$a]) $this->registerField($ain,$name,$s,$n,$t,$a);
                $h = $dev->hkr;
                foreach (['tist'=>'Actual','tsoll'=>'Setpoint','komfort'=>'Comfort','absenk'=>'Economy'] as $tag=>$field) {
                    $v = (string)$h->{$tag};
                    if (is_numeric($v) && (int)$v >= 0 && (int)$v <= 120) {
                        if ($tag === 'tsoll' || $tag === 'komfort' || $tag === 'absenk') {
                            if ((int)$v < 16 || (int)$v > 56) continue;
                        }
                        $this->setField($ain,$field,(int)$v/2);
                    }
                }
                $target = (string)$h->tsoll;
                if (is_numeric($target)) $this->setField($ain,'Mode',(int)$target === 253 ? 1 : ((int)$target === 254 ? 2 : 0));
                if (is_numeric((string)$h->battery)) $this->setField($ain,'Battery',(int)$h->battery);
                foreach (['batterylow'=>'BatteryLow','windowopenactiv'=>'WindowOpen','boostactive'=>'Boost'] as $tag=>$field) {
                    $v = (string)$h->{$tag};
                    if ($v === '0' || $v === '1') $this->setField($ain,$field,$v === '1');
                }
            }
        }
        $this->SetValue('LastError','');
        $this->SetStatus(102);
        $this->logDebug('Discovered '.$count.' controllable devices');
    }
}
