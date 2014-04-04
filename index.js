module.exports = function(accessKey) {
	var dns = require('dns'),
		HoneyPot = {};

	function validateAccessKey(accessKey) {

	}

	HoneyPot.query = function(ip, callback) {
		var octetReversedIP = ip.split('.').reverse().join('.');

		dns.lookup(accessKey + '.' + octetReversedIP + '.dnsbl.httpbl.org', 4, function(err, address) {
			if (err) {
				if (err.code === 'ENOTFOUND') {
					return callback(null, {
						ip: ip,
						found: false
					});
				} else {
					return callback(err);
				}
			}

			// Parse the returned address into user-consumable data
			var	octets = address.split('.'),
				type = parseInt(octets[3], 10),
				map = {
					suspicious: [1, 3, 5, 7],
					harvester: [2, 3, 6, 7],
					spammer: [4, 5, 6, 7]
				};

			callback(null, {
				ip: ip,
				found: true,
				lastSeenDays: parseInt(octets[1], 10),
				threatScore: type !== 0 ? parseInt(octets[2], 10) : 0,	// type of 0 indicates search engine, not a threat
				searchEngineId: type === 0 ? parseInt(octets[2], 10) : null,
				type: {
					searchEngine: type === 0 ? true : false,
					suspicious: map.suspicious.indexOf(type) !== -1,
					harvester: map.harvester.indexOf(type) !== -1,
					spammer: map.spammer.indexOf(type) !== -1
				}
			});
		});
	};

	return HoneyPot;
};