#Introduction
    This is a small project to create a HTTP 1.1-compliant webserver written in Python, partially for university, partially for myself.
    
#References
    The RFC for HTTP/1.1 is here: https://www.ietf.org/rfc/rfc2616.txt
    The inspiration for this project comes from: https://www.cs.cmu.edu/~prs/15-441-F16/project1/project1.pdf
    
#Architecture and Design
    The specifications for this are described by the RFC. This will be updated as I implement the webserver and look at how others have designed their servers.
    Specifically: 
    * Multi-threaded TCP communications to handle concurrent clients
    * User-specified host and other configuration options
    * Implementation of HEAD, POST, and GET HTTP 1.1 methods

#Deployment and Testing
    The server should be runnable on as a stand-alone executable or in a VM/separate machine to test its functions/capabilities.

#Future Additions
    Besides the base HTTP 1.1 standard implementation, I may also attempt to implement CGI (Common Gateway Interface).
