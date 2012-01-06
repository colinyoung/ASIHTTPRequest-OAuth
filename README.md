Purpose
=======

- Simplifies adding OAuth request headers to a ASIHTTPRequest/ASIFormDataRequest.

Usage
=====

1. Set up an ASIHTTPRequest normally

  ASIHTTPRequest* request = [ASIHTTPRequest
      requestWithURL: url];

2. Add the OAuth headers

  [request oauthifyWithConsumerKey:token:signatureMethod:version:]
