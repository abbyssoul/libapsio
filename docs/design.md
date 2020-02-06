# Server design

This library provides IO components to build asynchronious 9p servers.
That is Server class provides all that is required to listen for connection on a variety of protocols,
accept a connection, establish a session, authenticate session using configured strategy and serve requiests over 9p2000 protocol.

- Server configuration
- Listening for a connection
- Starting a session
- Authentication
- Processiong request
- Terminating a session
- Resource management
