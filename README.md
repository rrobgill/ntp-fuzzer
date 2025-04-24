# NTP fuzzer

Independent client and server to test NTP implementation

Server

NTPv4 server with packet fuzzing capabilities

This server responds to NTP client requests with:
- Responses based valid packets using the current system time,
- stratum 2, RefID 'Xntp', small random root dispersion & delay.
- User options to introduce error in server time offset (fixed
- and/or jittery), and random variation to root characteristics.
- Random errors can also be introduced into the response packets

Client

The client client generates NTP client requests based on current system time.
- Random errors are introduced into the request packets.



