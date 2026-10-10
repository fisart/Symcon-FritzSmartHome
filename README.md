# FRITZ! Smart Home – IP-Symcon

Module for FRITZ!DECT sockets and FRITZ!Smart Thermo 302 using AVM AHA HTTP API.

## Configuration

Install this repository in IP-Symcon Module Control, create one **FRITZ! Smart Home** instance per FRITZ!Box. Configure **SecretsManager Instance ID** (default `47118`) and **SecretsManager Key** (default `FB-DSL`). The SecretsManager's `SEC_GetSecret($instanceId, $key)` must return JSON with `IP`, `User`, and `PW`. Example *without credentials*: `{"IP":"192.168.20.1","User":"symcon","PW":"<secret>"}`. Use a different key for every box. No credentials are stored in instance properties or logs.

Set polling interval and enable the instance. Click **Discover now** or wait for the next poll. Every discovered device gets a dedicated **Dummy instance** below the FRITZ! Smart Home module instance. The Dummy is named exactly as in the FRITZ!Box. Socket and thermostat variables appear beneath it and use stable AIN-derived identifiers; AVM device renames update the Dummy name without creating new instances. Existing variables directly below the module are moved to their Dummy instances while retaining their object IDs and archive history. An internal hidden action script forwards switching and thermostat changes to the module.

### Sockets
Switch state, power (W), energy (kWh) and device temperature when supplied by the API.

### Thermostats
Actual and target temperature, comfort/economy temperature, battery percent/low status, online state and operating mode. Target temperature is actionable (8–28°C in 0.5°C steps). `Mode` actions: 0 = Automatic target restore (comfort setpoint), 1 = OFF (frost protection), 2 = ON (maximum heat). Use `Setpoint` to apply a manual target.

## Notes

* Device data requires connectivity and suitable device features. Unavailable measurements remain unchanged rather than being falsely zeroed.
* Login supports AVM legacy Challenge-Response. On failed login, inspect the `Last Error` and `Debug` variables. HTTP credentials/SIDs are never logged.
* This is an initial implementation. Test switching and thermostat control on a non-critical device before relying on it for unattended heating.
* AVM documentation: [AHA HTTP Interface](https://fritz.com/fileadmin/user_upload/Global/Service/Schnittstellen/AHA-HTTP-Interface.pdf).

## Set all thermostat target temperatures

Call from any IP-Symcon PHP script:

```php
$result = FSH_SetAllThermostatsTemperature($instanceID, 21.0);
echo $result; // JSON listing successful and failed thermostat updates
```

Accepted values: 8–28°C in 0.5°C increments. The method discovers HKR thermostats belonging to this FRITZ!Box, skips offline devices, issues `sethkrtsoll`, and verifies with `gethkrtsoll`. Each configured FRITZ!Box requires its own module instance; the call targets only the given instance.
