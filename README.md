# Generate Shared Access Signature like HMAC in .Net

 ```csharp
using ApiToken;

// Invoke class, can use Machine.Key in ASP.Net or some other controlled key.
var apiTokenService = new ApiTokenService("your-key-here");

// Expiration, allow some time for drift or use depending on need.
var expiration = DateTime.Now.AddMinutes(5);

// Generate token
// Example: uid=username-to-send&ex=2006-01-02T12:28:46.1769043-05:00&sn=sCpjZ4YehdID
//          ebSdC4NJxGf0yfYE/dtUA4Xk/HKFXCA7IrQ38cI6xyejiBIKXfg35rOYN+DzsLF7ZLXTjtxE9w==
var token = apiTokenService.GenerateToken("username-to-send", expiration);

// Encode Token in URL Safe Base64, obuscates values if desired.
// Example: dWlkPXVzZXJuYW1lLXRvLXNlbmQmZXg9MjAxNy0wMS0wOVQxMjoyODo0Ni4xNzY5MDQzLT
//          A1OjAwJnNuPXNDcGpaNFllaGRJRGViU2RDNE5KeEdmMHlmWUUvZHRVQTRYay9IS0ZYQ0E3S
//          XJRMzhjSTZ4eWVqaUJJS1hmZzM1ck9ZTitEenNMRjdaTFhUanR4RTl3PT0
var encodedToken = apiTokenService.UrlEncodeToken(token);
```
## Verify/Use 

 ```csharp
// Verify Token
var validToken = apiTokenService.ValidateToken(token);
Assert.IsTrue(validToken);

// Verify Encoded Token
var plainToken = apiTokenService.UrlDecodeToken(encodedToken);
var validEnCodedToken = apiTokenService.ValidateToken(plainToken);
Assert.IsTrue(validToken);

// Get user name from token
var username = apiTokenService.GetUidFromToken(token);
Assert.AreEqual("username-to-send", username);
```