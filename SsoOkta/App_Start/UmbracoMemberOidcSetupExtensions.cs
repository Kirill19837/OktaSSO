﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNet.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Serilog;

namespace SsoOkta.App_Start
{
    public static class UmbracoMemberOidcSetupExtensions
    {
        public static void UseIdentityServerForMemberAuthentication(this IAppBuilder app)
        {
            var authority = OidcConfiguration.Authority;
            var clientId = OidcConfiguration.Cms.ClientId;
            var clientSecret = OidcConfiguration.Cms.ClientSecret;
            var redirectUri = OidcConfiguration.Cms.RedirectUris;

            var identityOptions = new OpenIdConnectAuthenticationOptions
            {
                Caption = "Okta SSO",
                Authority = authority,
                ClientId = clientId,
                RedirectUri = redirectUri,
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                PostLogoutRedirectUri = OidcConfiguration.Cms.PostLogoutUris,
                Scope = "openid profile email",
                SaveTokens = true,
                SignInAsAuthenticationType = DefaultAuthenticationTypes.ExternalCookie,
                RequireHttpsMetadata = true,
                AuthenticationType = "Okta SSO"
            };

            identityOptions.Notifications = new OpenIdConnectAuthenticationNotifications
            {
                AuthorizationCodeReceived = async n => {
                    try
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
                            var nid = new ClaimsIdentity(id.AuthenticationType, ClaimTypes.GivenName, JwtClaimTypes.Role);

                            var sub = userInfoResponse.Claims.First(x => x.Type == JwtClaimTypes.Subject);
                            var roles = id.FindAll(JwtClaimTypes.Role);
                            var email = userInfoResponse.Claims.First(x => x.Type == JwtClaimTypes.Email);
                            nid.AddClaim(new Claim(ClaimTypes.GivenName, userInfoResponse.Claims.First(x => x.Type == JwtClaimTypes.GivenName).Value));
                            nid.AddClaim(new Claim(ClaimTypes.Email, email.Value));
                            nid.AddClaims(userInfoResponse.Claims.Where(x => x != email));
                            nid.AddClaim(sub);
                            nid.AddClaims(roles);
                            nid.AddClaim(new Claim(ClaimTypes.NameIdentifier, sub.Value, "http://www.w3.org/2001/XMLSchema#string", DefaultAuthenticationTypes.ExternalCookie));

                            n.AuthenticationTicket = new AuthenticationTicket(nid, n.AuthenticationTicket.Properties);

                            var cookieOptions = new CookieOptions()
                            {
                                Secure = true,
                                SameSite = SameSiteMode.Strict,
                                Expires = DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn)
                            };

                            n.Response.Cookies.Append("pm_access_token", tokenResponse.AccessToken, cookieOptions);
                            cookieOptions.Expires = DateTime.UtcNow.AddDays(15);
                            n.Response.Cookies.Append("pm_refresh_token", tokenResponse.RefreshToken, cookieOptions);
                        }
                    }
                    catch (Exception e)
                    {
                        Log.Error(e,
                         "An error occured when trying to log in a member.");
                    }
                }
            };


            app.UseOpenIdConnectAuthentication(identityOptions);
        }
    }
}