module.exports = function(client, callback) {

	dns.lookup('nodejs.org', 4, function(err, address, family) {
		if (global.geoip) {
			client.context.data = {
				req: {
					connection: {
						remoteAddress: client.req.connection.remoteAddress,
						geoip: geoip.lookup(client.req.connection.remoteAddress)
					}
				},
				example: {
					nodejs: {
						host: 'nodejs.org',
						geoip: geoip.lookup(address)
					}
				}
			}
		} else client.context.data = 'GeoIP plugin is not loaded';
		callback();
	});

}