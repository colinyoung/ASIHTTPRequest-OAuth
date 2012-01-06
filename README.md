Purpose
=======

- Simplifies adding OAuth request headers to a TTURLRequest.

Usage
=====

1. Set up a TTURLRequest normally

   TTURLRequest* request = [TTURLRequest
       requestWithURL: url
       delegate: self];

2. Add the OAuth headers

   [request oauthifyWithConsumerKey:token:signatureMethod:version:]
