Student : Venkatesh Gopal
Email ID: vgopal3@jhu.edu

This software is not to be distributed without acquiring appropriate permission from vgopal3@jhu.edu.

Usage:

1. Open CertFactory.py and enter the location of the certificates (user1, Root CA, Intermediate CA) and private key
2. Run secureTCP.py directly from command line.

Additional Information:

This software uses another framework which is not listed in this documentation. I use that framework for providing a stack over TCP so the I could run any application over it.
Though this is a demonstration of secure TCP, it is a proof of concept for how security features could be added to TCP with minimal loss in efficiency.
For Usage/Testing of this software, Contact vgopal3@jhu.edu

Description:

The Entire TCP runs on the Internet. However, TCP by itself is insecure and that is the reason we require SSL over layer 4 to provide authentication, confidentiality and integrity to applicaitons.
In this project, I show how authentication, confidentiality and integrity could be added to TCP. With the SecureTCP, every TCP packet contains a signature to prove the authenticity of the sending entity.

Refer to source coude/ contact author vgopal3@jhu.edu for more details.
Attached is a private RFC which describes the technical aspects
