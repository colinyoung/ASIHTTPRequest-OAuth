/*
 
 // 2012 Colin Young

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
 
*/
#import "Three20/Three20.h"
#import "ASIHTTPRequest.h"

typedef enum {
    ASIHTTPRequestOAuthSignatureMethodPlaintext,
    ASIHTTPRequestOAuthSignatureMethodHMAC,
    ASIHTTPRequestOAuthSignatureMethodRSA
} ASIHTTPRequestOAuthSignatureMethod;

@interface ASIHTTPRequest (OAuth)

-(void)oauthifyWithConsumerKey:(NSString *)consumerKey
                         token:(NSString *)token
               signatureMethod:(ASIHTTPRequestOAuthSignatureMethod)signatureMethod
                       version:(NSString *)version;

// @private
+(NSString *)stringForSignatureMethod:(ASIHTTPRequestOAuthSignatureMethod)signatureMethod;
+(NSString *)nonce:(int)length;

@end
