# Server testing points:

9P Is steteful protocol with 3 destrinct states:
[Initial(No version negotiated] -> [NotAttached(No auth/attache called)] -> [Session]

- Version request -> Auth,Attach -> walk -> Version: whould
it is possible to transition from [intial state] -> [session] -> [NotAttached] by sending `TAttach` in a session state.
All opened FIDs must be clunked as a result.

- TWalk provides fid for a new file walked to. Make sure this fid is not in use.

- Auth -> Auth -> Auth?
