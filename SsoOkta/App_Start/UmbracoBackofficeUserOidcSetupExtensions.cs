using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Newtonsoft.Json;
using Owin;
using Umbraco.Core;
using Umbraco.Core.Composing;
using Umbraco.Core.Models.Identity;
using Umbraco.Core.Models.Membership;
using Umbraco.Core.Services;
using Umbraco.Web.Security;

namespace SsoOkta.App_Start
{
    public static class UmbracoBackofficeUserOidcSetupExtensions
    {
        public static void UseIdentityServerForUserAuthentication(this IAppBuilder app)
        {
            var authority = OidcConfiguration.Authority;
            var clientId = OidcConfiguration.Backoffice.ClientId;
            var clientSecret = OidcConfiguration.Backoffice.ClientSecret;
            var redirectUri = OidcConfiguration.Backoffice.RedirectUris;

            var identityOptions = new OpenIdConnectAuthenticationOptions
            {
                Authority = authority,
                ClientId = clientId,
                ClientSecret = clientSecret,
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                RedirectUri = redirectUri,
                PostLogoutRedirectUri = OidcConfiguration.Backoffice.PostLogoutUris,
                Scope = "openid profile email",
                SaveTokens = true,
                RequireHttpsMetadata = true,
                SignInAsAuthenticationType =  Constants.Security.BackOfficeExternalAuthenticationType,
            };
            identityOptions.ForUmbracoBackOffice("btn-blue", "fa-sign-in-alt");
            identityOptions.Caption = "Okta Sso";
            identityOptions.AuthenticationType = authority;

            var autoLinkOptions = new ExternalSignInAutoLinkOptions(true, new[] { "editor" })
            {
                AllowManualLinking = false,
                OnAutoLinking = SetRolesAndGroups,

                OnExternalLogin = (identityUser, info) =>
                {
                    SetRolesAndGroups(identityUser, info);
                    return true;
                }
            };

            identityOptions.SetBackOfficeExternalLoginProviderOptions(
                new BackOfficeExternalLoginProviderOptions()
                {
                    AutoLinkOptions = autoLinkOptions,
                    DenyLocalLogin = true
                });

            identityOptions.Notifications = new OpenIdConnectAuthenticationNotifications
            {
                AuthorizationCodeReceived = async n =>
                {
                    using (var client = new HttpClient())
                    {
                        var disco = await client.GetDiscoveryDocumentAsync(authority);

                        var tokenResponse = await client.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
                        {
                            Address = disco.TokenEndpoint,

                            ClientId = clientId,
                            ClientSecret = clientSecret,

                            Code = n.Code,
                            RedirectUri = n.RedirectUri
                        });

                        if (tokenResponse.IsError)
                            throw new Exception(tokenResponse.Error);

                        var userInfoResponse = await client.GetUserInfoAsync(new UserInfoRequest
                        {
                            Address = disco.UserInfoEndpoint,
                            Token = tokenResponse.AccessToken
                        });
                        
                        var id = n.AuthenticationTicket.Identity;
                        var nid = new ClaimsIdentity(id.AuthenticationType, ClaimTypes.GivenName, ClaimTypes.Role);

                        var sub = userInfoResponse.Claims.First(x => x.Type == JwtClaimTypes.Subject);

                        nid.AddClaim(sub);
                        nid.AddClaim(new Claim(ClaimTypes.Email, userInfoResponse.Claims.First(x => x.Type == JwtClaimTypes.Email).Value));
                        nid.AddClaim(new Claim(ClaimTypes.GivenName, userInfoResponse.Claims.First(x => x.Type == JwtClaimTypes.GivenName).Value));
                        nid.AddClaim(new Claim(ClaimTypes.Surname, userInfoResponse.Claims.First(x => x.Type == JwtClaimTypes.FamilyName).Value));
                        nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                        nid.AddClaim(new Claim("access_token", tokenResponse.AccessToken));
                        nid.AddClaim(new Claim("expires_at", DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime().ToString(CultureInfo.InvariantCulture)));
                        nid.AddClaim(new Claim(ClaimTypes.NameIdentifier, sub.Value, "http://www.w3.org/2001/XMLSchema#string", OidcConfiguration.Authority));
                        
                        n.AuthenticationTicket = new AuthenticationTicket(nid, n.AuthenticationTicket.Properties);

                        var cookieOptions = new CookieOptions()
                        {
                            Secure = true,
                            SameSite = SameSiteMode.Strict,
                            Expires = DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn)
                        };

                        n.Response.Cookies.Append("access_token", tokenResponse.AccessToken, cookieOptions);
                        cookieOptions.Expires = DateTime.UtcNow.AddDays(15);
                        n.Response.Cookies.Append("refresh_token", tokenResponse.RefreshToken, cookieOptions);
                    }
                }
            };

            app.UseOpenIdConnectAuthentication(identityOptions);
        }

        private static void SetRolesAndGroups(BackOfficeIdentityUser identityUser, ExternalLoginInfo info)
        {
            var userService = Current.Factory.GetInstance<IUserService>();
            var allUserGroups = userService.GetAllUserGroups();
            var matchedRoles = allUserGroups.OfType<IReadOnlyUserGroup>().ToList();
            identityUser.Groups = matchedRoles.ToArray();
            foreach (var matchedRole in matchedRoles)
            {
                identityUser.Roles.Add(new IdentityUserRole<string>
                {
                    UserId = identityUser.Id.ToString(),
                    RoleId = matchedRole.Alias
                });
            }

            var user = userService.GetUserById(identityUser.Id);
            if (user == null)
            {
                return;
            }
            user.ClearGroups();
            foreach (var matchedRole in matchedRoles)
            {
                user.AddGroup(matchedRole);
            }

            userService.Save(user);
        }
    }
}