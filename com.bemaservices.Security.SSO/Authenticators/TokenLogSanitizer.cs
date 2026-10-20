using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace com.bemaservices.Security.SSO.Authenticators
{
    internal static class TokenLogSanitizer
    {
        private const string REDACTED_TOKEN_VALUE = "[REDACTED]";

        internal static string SanitizeJsonForLogging( string responseContent )
        {
            if ( string.IsNullOrWhiteSpace( responseContent ) )
            {
                return string.Empty;
            }

            try
            {
                var responseJson = JToken.Parse( responseContent );
                if ( responseJson.Type != JTokenType.Object && responseJson.Type != JTokenType.Array )
                {
                    return "[Response omitted because it is not a JSON object or array]";
                }

                RedactTokenValues( responseJson );
                return responseJson.ToString( Formatting.None );
            }
            catch ( JsonReaderException )
            {
                return "[Response omitted because it is not valid JSON]";
            }
        }

        internal static string RedactTokenForLogging( string token )
        {
            return string.IsNullOrWhiteSpace( token ) ? string.Empty : REDACTED_TOKEN_VALUE;
        }

        private static void RedactTokenValues( JToken token )
        {
            var jsonObject = token as JObject;
            if ( jsonObject != null )
            {
                foreach ( var property in jsonObject.Properties() )
                {
                    if ( property.Name.EndsWith( "token", StringComparison.OrdinalIgnoreCase ) )
                    {
                        property.Value = REDACTED_TOKEN_VALUE;
                    }
                    else
                    {
                        RedactTokenValues( property.Value );
                    }
                }

                return;
            }

            var jsonArray = token as JArray;
            if ( jsonArray != null )
            {
                foreach ( var item in jsonArray )
                {
                    RedactTokenValues( item );
                }
            }
        }
    }
}
