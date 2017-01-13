using System;
using ApiToken;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ApiTokenUnitTest
{
    [TestClass]
    public class ApiTokenServiceTest
    {
        private string _username;
        private ApiTokenService _apiTokenService;

        [TestInitialize]
        public void TestInitialize()
        {
            _apiTokenService = new ApiTokenService("n)4]0ummyrhvg9bLOa~Mzrr*u8[dDJFhC3RMB/a6IuiImf96KA0?mZ+5RfIgCXO");

            // test with all ascii chars https://en.wikipedia.org/wiki/ASCII
            for (var i = 32; i <= 126; i++)
            {
                _username += new string(new [] { (char)i });
            }
        }

        [TestMethod]
        public void UsageTest()
        {
            // Invoke class, can use Machine.Key in ASP.Net or some other controlled key.
            var apiTokenService = new ApiTokenService("your-key-here");

            // Expiration, allow some time for drift, but not enough for a replay attack
            var expiration = DateTime.Now.AddMinutes(5);

            // Generate token
            // Example: uid=username-to-send&ex=2006-01-02T12:28:46.1769043-05:00&sn=sCpjZ4YehdIDebSdC4NJxGf0yfYE/dtUA4Xk/HKFXCA7IrQ38cI6xyejiBIKXfg35rOYN+DzsLF7ZLXTjtxE9w==
            var token = apiTokenService.GenerateToken("username-to-send", expiration);

            // Encode Token in URL Safe Base64, obuscates values if desired.
            // Example: dWlkPXVzZXJuYW1lLXRvLXNlbmQmZXg9MjAxNy0wMS0wOVQxMjoyODo0Ni4xNzY5MDQzLTA1OjAwJnNuPXNDcGpaNFllaGRJRGViU2RDNE5KeEdmMHlmWUUvZHRVQTRYay9IS0ZYQ0E3SXJRMzhjSTZ4eWVqaUJJS1hmZzM1ck9ZTitEenNMRjdaTFhUanR4RTl3PT0
            //var encodedToken = apiTokenService.UrlEncodeToken(token);
          
            // *** Transmit token (unencoded or encoded)

            // Verify Token
            var validToken = apiTokenService.ValidateToken(token);
            Assert.IsTrue(validToken);

            // Verify Encoded Token
            //var plainToken = apiTokenService.UrlDecodeToken(encodedToken);
            //var validEnCodedToken = apiTokenService.ValidateToken(plainToken);
            //Assert.IsTrue(validToken);

            // Get user name from token
            var username = apiTokenService.GetUidFromToken(token);
            Assert.AreEqual("username-to-send", username);
        }

        [TestMethod]
        public void ValidateToken()
        {
            var exp = DateTime.Now.AddMinutes(15);
            var token = _apiTokenService.GenerateToken(_username, exp);
            var valid = _apiTokenService.ValidateToken(token);
            Assert.IsTrue(valid);
        }

        [TestMethod]
        public void GetUidFromToken()
        {
            var exp = DateTime.Now.AddMinutes(15);
            var token = _apiTokenService.GenerateToken(_username, exp);
            var uid = _apiTokenService.GetUidFromToken(token);
            Assert.AreEqual(_username, uid);
        }

        [TestMethod]
        public void ExpiredToken()
        {
            var exp = DateTime.Now;
            var token = _apiTokenService.GenerateToken(_username, exp);
            var valid = _apiTokenService.ValidateToken(token);
            Assert.IsFalse(valid);
        }

        [TestMethod]
        public void GetUidFromExpiredToken()
        {
            var exp = DateTime.Now;
            var token = _apiTokenService.GenerateToken(_username, exp);
            var uid = _apiTokenService.GetUidFromToken(token);
            Assert.IsNull(uid);
        }

        //[TestMethod]
        //public void TokenUrlEncoding()
        //{
        //    var exp = DateTime.Now.AddMinutes(15);
        //    var token = _apiTokenService.GenerateToken(_username, exp);
        //    var encodedToken = _apiTokenService.UrlEncodeToken(token);
        //    var decodedToken = _apiTokenService.UrlDecodeToken(encodedToken);
        //    Assert.AreEqual(token, decodedToken);
        //}
    }
}
