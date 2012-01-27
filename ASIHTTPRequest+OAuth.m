#import "ASIHTTPRequest+OAuth.h"
#import "RandomString.h"
#import "OAHMAC_SHA1SignatureProvider.h"
#import "OAPlaintextSignatureProvider.h"

#define kDefaultNonceLength 20

@interface ASIHTTPRequest (OAuth_Private)

+(NSString *)signatureStringWithURL:(NSURL*)URL
                         httpMethod:(NSString *)httpMethod
                    signatureMethod:(ASIHTTPRequestOAuthSignatureMethod)signatureMethod
                        accessToken:(NSString *)token 
                        tokenSecret:(NSString *)tokenSecret
                     consumerSecret:(NSString *)consumerSecret
                  requestParameters:(NSDictionary *)requestParameters;

+(NSString *)nonce:(int)length;

+(NSString *)stringForSignatureMethod:(ASIHTTPRequestOAuthSignatureMethod)signatureMethod;

+ (NSString *)signatureBaseStringWithURL:(NSURL*)URL
                              httpMethod:(NSString *)httpMethod
                       requestParameters:(NSDictionary *)requestParameters;

@end

@implementation ASIHTTPRequest (OAuth)

-(void)oauthifyWithConsumerKey:(NSString *)consumerKey
                consumerSecret:(NSString *)consumerSecret
                   accessToken:(NSString *)accessToken
             accessTokenSecret:(NSString *)accessTokenSecret
               signatureMethod:(ASIHTTPRequestOAuthSignatureMethod)signatureMethod
                       version:(NSString *)version {
    
    NSMutableDictionary *HTTPAuthorization = [NSMutableDictionary dictionaryWithCapacity:4];
    [HTTPAuthorization setObject:consumerKey forKey:@"oauth_consumer_key"];
    if (accessToken) [HTTPAuthorization setObject:accessToken forKey:@"oauth_token"];
    [HTTPAuthorization setObject:[[self class] stringForSignatureMethod:signatureMethod] forKey:@"oauth_signature_method"];
    [HTTPAuthorization setObject:[NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]] forKey:@"oauth_timestamp"];
    [HTTPAuthorization setObject:accessToken forKey:@"oauth_token"];
    [HTTPAuthorization setObject:[[self class] nonce:kDefaultNonceLength] forKey:@"oauth_nonce"];
    if (version) [HTTPAuthorization setObject:version forKey:@"oauth_version"];
    
    if (!TTIsStringWithAnyText([self requestMethod])) [self setRequestMethod:@"GET"];
    
    [HTTPAuthorization setObject:[[self class] signatureStringWithURL:[self url]
                                                           httpMethod:[self requestMethod]
                                                      signatureMethod:signatureMethod
                                                          accessToken:accessToken
                                                          tokenSecret:accessTokenSecret                                  
                                                       consumerSecret:consumerSecret
                                                    requestParameters:HTTPAuthorization] forKey:@"oauth_signature"];
    
    // Doing this inline so this lib doesn't have any dependencies
    NSMutableString *HTTPAuthorizationString = [NSMutableString string];
    
    int i = 0;
    for (NSString *key in HTTPAuthorization) {
        i++;        
        [HTTPAuthorizationString appendFormat:@"%@=%@", key, [HTTPAuthorization objectForKey:key]];
        if (i < [[HTTPAuthorization allKeys] count]) [HTTPAuthorizationString appendString:@"&"];
    }
    
    [self addRequestHeader:@"Authorization" value:HTTPAuthorizationString];
}

#pragma mark - Private
+(NSString *)stringForSignatureMethod:(TTURLRequestOAuthSignatureMethod)_signatureMethod {
    switch (_signatureMethod) {
        case TTURLRequestOAuthSignatureMethodHMAC:
            return @"HMAC-SHA1";
            break;
            
        case TTURLRequestOAuthSignatureMethodRSA:
            return @"RSA-SHA1";
            break;
            
        case TTURLRequestOAuthSignatureMethodPlaintext:
        default:
            return @"PLAINTEXT";
    }
    return @"PLAINTEXT";
}

+(NSString *)nonce:(int)length {
    char cNonce[length];
    randomString(cNonce, length);
    NSString *nonce = [[[NSString alloc] initWithUTF8String:cNonce] autorelease];
    if (!TTIsStringWithAnyText(nonce)) return @"";    
    return nonce;
}

#pragma mark - Signature
+(NSString *)signatureStringWithURL:(NSURL*)URL
                         httpMethod:(NSString *)httpMethod
                    signatureMethod:(TTURLRequestOAuthSignatureMethod)signatureMethod
                        accessToken:(NSString *)token 
                        tokenSecret:(NSString *)tokenSecret
                     consumerSecret:(NSString *)consumerSecret
                  requestParameters:(NSDictionary *)requestParameters {
    
    id <OASignatureProviding> provider = nil;
    if (signatureMethod == TTURLRequestOAuthSignatureMethodHMAC) {
        provider = [[OAHMAC_SHA1SignatureProvider alloc] init];
    } else {
        provider = [[OAPlaintextSignatureProvider alloc] init];
    }  
    
    NSString *signature = [provider signClearText:[[self class] signatureBaseStringWithURL:URL
                                                                                httpMethod:httpMethod
                                                                         requestParameters:requestParameters]
                                       withSecret:[NSString stringWithFormat:@"%@&%@",
                                                   [consumerSecret urlEncoded],
                                                   [tokenSecret urlEncoded]]];
    
    return [NSString stringWithString:[signature urlEncoded]];
}

/* Original source of this method from http://oauth.googlecode.com/svn/code/obj-c/OAuthConsumer/ */
+ (NSString *)signatureBaseStringWithURL:(NSURL*)URL
                              httpMethod:(NSString *)httpMethod
                       requestParameters:(NSDictionary *)requestParameters
{
    // OAuth Spec, Section 9.1.1 "Normalize Request Parameters"
    // build a sorted array of both request parameters and OAuth header parameters
    NSMutableArray *parameterPairs = [NSMutableArray  arrayWithCapacity:(6 + [requestParameters count])]; // 6 being the number of OAuth params in the Signature Base String
    
    NSArray *params = [NSArray arrayWithObjects: \
                       @"oauth_consumer_key", 
                       @"oauth_signature_method", 
                       @"oauth_timestamp", 
                       @"oauth_nonce",
                       @"oauth_token",
                       @"oauth_version", nil];
    
    for (NSString *key in params) {
        [parameterPairs addObject:[[NSString stringWithFormat:@"%@=%@", key, [requestParameters objectForKey:key]] urlEncoded]];
    }
    
    NSArray *sortedPairs = [parameterPairs sortedArrayUsingSelector:@selector(compare:)];
    NSString *normalizedRequestParameters = [sortedPairs componentsJoinedByString:@"&"];
    
    
    // OAuth Spec, Section 9.1.2 "Concatenate Request Elements"
    NSString *URLStringWithoutQuery = [[[URL absoluteString] componentsSeparatedByString:@"?"] firstObject];
    NSString *ret = [NSString stringWithFormat:@"%@&%@&%@",
					 httpMethod,
					 [URLStringWithoutQuery urlEncoded],
					 [normalizedRequestParameters urlEncoded]];
    
	return ret;
}

@end
