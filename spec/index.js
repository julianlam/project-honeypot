var mocha = require('mocha'),
    assert = require('assert'),
    honeypot = require('..')(process.env.KEY);

/*
    Test Values for Project Honeypot

    SIMULATE NO RECORD RETURNED
    Query       Expected Response
    127.0.0.1   NXDOMAIN

    SIMULATE DIFFERENT TYPES
    Query       Expected Response
    127.1.1.0   127.1.1.0
    127.1.1.1   127.1.1.1
    127.1.1.2   127.1.1.2
    127.1.1.3   127.1.1.3
    127.1.1.4   127.1.1.4
    127.1.1.5   127.1.1.5
    127.1.1.6   127.1.1.6
    127.1.1.7   127.1.1.7

    SIMULATE DIFFERENT THREAT LEVELS
    Query       Expected Response
    127.1.10.1  127.1.10.1
    127.1.20.1  127.1.20.1
    127.1.40.1  127.1.40.1
    127.1.80.1  127.1.80.1

    SIMULATE DIFFERENT NUMBER OF DAYS
    Query       Expected Response
    127.10.1.1  127.10.1.1
    127.20.1.1  127.20.1.1
    127.40.1.1  127.40.1.1
    127.80.1.1  127.80.1.1
*/

describe('HoneyPot', function() {
    describe('.query', function() {
        it('should report "not found" for 127.0.0.1', function(done) {
            honeypot.query('127.0.0.1', function(err, data) {
                process.exit();
                assert(data);
                assert.equal(false, data.found);
                done();
            });
        });

        describe('Types', function() {
            it('should report 127.1.1.0 as a search engine', function(done) {
                honeypot.query('127.1.1.0', function(err, data) {
                    assert(data);
                    assert.equal(true, data.found);
                    assert.equal(true, data.type.searchEngine);
                    assert.equal(true, data.searchEngineId);
                    assert.equal(false, data.type.suspicious);
                    assert.equal(false, data.type.harvester);
                    assert.equal(false, data.type.spammer)
                    done();
                });
            });

            it('should report 127.1.1.1 as "suspicious"', function(done) {
                honeypot.query('127.1.1.1', function(err, data) {
                    assert(data);
                    assert.equal(true, data.found);
                    assert.equal(false, data.type.searchEngine);
                    assert.equal(null, data.searchEngineId);
                    assert.equal(true, data.type.suspicious);
                    assert.equal(false, data.type.harvester);
                    assert.equal(false, data.type.spammer);
                    done();
                });
            });

            it('should report 127.1.1.2 as a "harvester"', function(done) {
                honeypot.query('127.1.1.2', function(err, data) {
                    assert(data);
                    assert.equal(true, data.found);
                    assert.equal(false, data.type.searchEngine);
                    assert.equal(null, data.searchEngineId);
                    assert.equal(false, data.type.suspicious);
                    assert.equal(true, data.type.harvester);
                    assert.equal(false, data.type.spammer)
                    done();
                });
            });

            it('should report 127.1.1.3 as both "suspicious" and "harvester"', function(done) {
                honeypot.query('127.1.1.3', function(err, data) {
                    assert(data);
                    assert.equal(true, data.found);
                    assert.equal(false, data.type.searchEngine);
                    assert.equal(null, data.searchEngineId);
                    assert.equal(true, data.type.suspicious);
                    assert.equal(true, data.type.harvester);
                    assert.equal(false, data.type.spammer)
                    done();
                });
            });

            it('should report 127.1.1.4 as a "spammer"', function(done) {
                honeypot.query('127.1.1.4', function(err, data) {
                    assert(data);
                    assert.equal(true, data.found);
                    assert.equal(false, data.type.searchEngine);
                    assert.equal(null, data.searchEngineId);
                    assert.equal(false, data.type.suspicious);
                    assert.equal(false, data.type.harvester);
                    assert.equal(true, data.type.spammer)
                    done();
                });
            });

            it('should report 127.1.1.5 as both "suspicious" and "spammer"', function(done) {
                honeypot.query('127.1.1.5', function(err, data) {
                    assert(data);
                    assert.equal(true, data.found);
                    assert.equal(false, data.type.searchEngine);
                    assert.equal(null, data.searchEngineId);
                    assert.equal(true, data.type.suspicious);
                    assert.equal(false, data.type.harvester);
                    assert.equal(true, data.type.spammer)
                    done();
                });
            });

            it('should report 127.1.1.6 as both "harvester" and "spammer"', function(done) {
                honeypot.query('127.1.1.6', function(err, data) {
                    assert(data);
                    assert.equal(true, data.found);
                    assert.equal(false, data.type.searchEngine);
                    assert.equal(null, data.searchEngineId);
                    assert.equal(false, data.type.suspicious);
                    assert.equal(true, data.type.harvester);
                    assert.equal(true, data.type.spammer)
                    done();
                });
            });

            it('should report 127.1.1.7 as "suspicious", "harvester", and "spammer"', function(done) {
                honeypot.query('127.1.1.7', function(err, data) {
                    assert(data);
                    assert.equal(true, data.found);
                    assert.equal(false, data.type.searchEngine);
                    assert.equal(null, data.searchEngineId);
                    assert.equal(true, data.type.suspicious);
                    assert.equal(true, data.type.harvester);
                    assert.equal(true, data.type.spammer)
                    done();
                });
            });
        });

        describe('Threat Levels', function() {
            it('should report a threat level of 10 for ip "127.1.10.1"', function(done) {
                honeypot.query('127.1.10.1', function(err, data) {
                    assert(data);
                    assert.strictEqual(10, data.threatScore);
                    done();
                });
            });

            it('should report a threat level of 20 for ip "127.1.20.1"', function(done) {
                honeypot.query('127.1.20.1', function(err, data) {
                    assert(data);
                    assert.strictEqual(20, data.threatScore);
                    done();
                });
            });

            it('should report a threat level of 40 for ip "127.1.40.1"', function(done) {
                honeypot.query('127.1.40.1', function(err, data) {
                    assert(data);
                    assert.strictEqual(40, data.threatScore);
                    done();
                });
            });

            it('should report a threat level of 80 for ip "127.1.80.1"', function(done) {
                honeypot.query('127.1.80.1', function(err, data) {
                    assert(data);
                    assert.strictEqual(80, data.threatScore);
                    done();
                });
            });
        });

        describe('Last Seen Days', function() {
            it('should report a "last seen" of 10 days for "127.10.1.1"', function(done) {
                honeypot.query('127.10.1.1', function(err, data) {
                    assert(data);
                    assert.strictEqual(10, data.lastSeenDays);
                    done();
                });
            });

            it('should report a "last seen" of 20 days for "127.20.1.1"', function(done) {
                honeypot.query('127.20.1.1', function(err, data) {
                    assert(data);
                    assert.strictEqual(20, data.lastSeenDays);
                    done();
                });
            });

            it('should report a "last seen" of 40 days for "127.40.1.1"', function(done) {
                honeypot.query('127.40.1.1', function(err, data) {
                    assert(data);
                    assert.strictEqual(40, data.lastSeenDays);
                    done();
                });
            });

            it('should report a "last seen" of 80 days for "127.80.1.1"', function(done) {
                honeypot.query('127.80.1.1', function(err, data) {
                    assert(data);
                    assert.strictEqual(80, data.lastSeenDays);
                    done();
                });
            });
        });
    });
});