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

/*
    No tests yet :(
*/