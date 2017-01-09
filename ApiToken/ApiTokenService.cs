using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using Microsoft.IdentityModel.Tokens;

namespace ApiToken
{
    public class ApiTokenService
    {
        private readonly string _key;
        public ApiTokenService(string key)
        {
            _key = key;
        }
        public string GenerateSignature(string userName, DateTime expiry)
        {
            using (var encoder = new HMACSHA512(Encoding.UTF8.GetBytes(_key)))
            {
                var dataToSign = userName + "\n" + FormatExirationDate(expiry);
                var hash = encoder.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
                var signature = Convert.ToBase64String(hash);
                return signature;
            }
        }
        public string FormatExirationDate(DateTime expiry)
        {
            return expiry.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        }
        public string GenerateToken(string userName, DateTime expiry)
        {
            var encodedUserName = HttpUtility.UrlEncode(userName);
            var signature = GenerateSignature(encodedUserName, expiry.ToUniversalTime());
            var token = $"uid={encodedUserName}&ex={expiry:o}&sn={signature}";
            return token;
        }
        public bool ValidateToken(string token)
        {
            if (string.IsNullOrEmpty(token)) // No token
                return false;

            try
            {
                // Read values from Token
                var tokenValues = ParseToken(token);
                if (tokenValues == null)
                    return false;
                var userName = tokenValues["uid"];
                var expiry = tokenValues["ex"];
                var signature = tokenValues["sn"];

                // Check Expiration
                DateTime expiryDate;
                if (!DateTime.TryParse(expiry, out expiryDate))
                {
                    return false;
                }
                var universalExpiryDate = expiryDate.ToUniversalTime();

                if (universalExpiryDate <= DateTime.UtcNow) // Token Expired
                    return false;

                // Validate Signature
                var signatureValidation = GenerateSignature(userName, universalExpiryDate);
                var validToken = signature.Equals(signatureValidation, StringComparison.Ordinal);

                return validToken;
            }
            catch
            {
                // Don't leak internal errors
                return false;
            }
        }
        public string GetUidFromToken(string token)
        {
            var tokenValues = ParseToken(token);
            if (tokenValues == null)
                return null;
            if (!ValidateToken(token))
                return null;
            return HttpUtility.UrlDecode(tokenValues["uid"]);
        }
        public string UrlEncodeToken(string token)
        {
            return Base64UrlEncoder.Encode(token);
        }
        public string UrlDecodeToken(string token)
        {
            return Base64UrlEncoder.Decode(token);
        }
        private Dictionary<string, string> ParseToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            return Regex.Matches(token, "([^?=&]+)(=([^&]*))?").Cast<Match>().ToDictionary(x => x.Groups[1].Value, x => x.Groups[3].Value);
        }
    }
}