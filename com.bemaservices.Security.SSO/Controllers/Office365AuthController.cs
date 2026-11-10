using System.Net;
using System.Web.Http;
using com.bemaservices.Security.SSO.Authenticators;
using Newtonsoft.Json;
using RestSharp;
using Rock.Security;

namespace Rock.Rest.Controllers
{
    public class Office365AuthController : ApiController
    {
        [AllowAnonymous]
        [HttpPost]
        [Route( "api/Office365Auth/AuthLogin" )]
        public IHttpActionResult AuthLogin( [FromBody] Office365AuthRequest request )
        {
            if ( request == null || string.IsNullOrWhiteSpace( request.AccessToken ) )
            {
                return BadRequest( "An Azure / Office 365 access token is required." );
            }

            var restClient = new RestClient( "https://graph.microsoft.com" );
            var restRequest = new RestRequest( "v1.0/me", Method.GET );
            restRequest.AddHeader( "Authorization", "Bearer " + request.AccessToken );
            var restResponse = restClient.Execute( restRequest );

            if ( restResponse.StatusCode == HttpStatusCode.Unauthorized
                || restResponse.StatusCode == HttpStatusCode.Forbidden
                || restResponse.StatusCode == HttpStatusCode.BadRequest )
            {
                return Unauthorized();
            }

            if ( restResponse.StatusCode != HttpStatusCode.OK )
            {
                return Content( HttpStatusCode.BadGateway, "Microsoft Graph could not validate the access token." );
            }

            if ( string.IsNullOrWhiteSpace( restResponse.Content ) )
            {
                return Content( HttpStatusCode.BadGateway, "Microsoft Graph returned an empty user profile." );
            }

            Office365.Office365_User office365User;
            try
            {
                office365User = JsonConvert.DeserializeObject<Office365.Office365_User>( restResponse.Content );
            }
            catch ( JsonException )
            {
                return Content( HttpStatusCode.BadGateway, "Microsoft Graph returned an invalid user profile." );
            }

            string userName = Office365.GetOffice365User( office365User, request.AccessToken );
            if ( string.IsNullOrWhiteSpace( userName ) )
            {
                return Unauthorized();
            }

            Rock.Security.Authorization.SetAuthCookie( userName, request.Persisted, false, true );

            return Ok( new { userName } );
        }
    }

    public class Office365AuthRequest
    {
        public string AccessToken { get; set; }

        public bool Persisted { get; set; }
    }
}
