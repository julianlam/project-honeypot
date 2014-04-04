# Project Honeypot

This npm module will allow you to query and consume the Project Honeypot API. Query it with an IP, and a simple JSON object will be sent back with relevent metadata regarding that IP.

## Installation

    npm install project-honeypot

## Usage

1. Register for an account at [Project Honeypot](https://www.projecthoneypot.org).
1. Enable API access and receive an access key.
1. Use this code:

``` js
    var honeypot = require('project-honeypot')('YOUR-ACCESS-KEY');

    honeypot.query(ip, callback);
```

## Callback

Callback signature is `(err, payload)`, and follows the following format:

1. If the IP address not found, `payload.found` is boolean `false`
1. Otherwise, `payload.found` is boolean `true` and shows follows this format:

``` json
{
  "ip": "127.1.1.5",
  "found": true,
  "lastSeenDays": 1,
  "threatScore": 1,
  "searchEngineId": null,
  "type": {
    "searchEngine": false,
    "suspicious": true,
    "harvester": false,
    "spammer": true
  }
}
```

**Note**: Certain ip addresses in the `127.*.*.*` range are test addresses, `127.1.1.5` being one of them. It returns a result record corresponding to a IP address flagged as both "suspicious" and "comment spammer". [View the full list here](https://www.projecthoneypot.org/httpbl_api.php).

## License

[MIT](http://opensource.org/licenses/MIT)