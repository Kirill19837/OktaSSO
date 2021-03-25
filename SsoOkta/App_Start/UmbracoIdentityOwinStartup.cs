using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using System;
using System.Configuration;
using System.Linq;
using Microsoft.IdentityModel.Logging;
using UmbracoIdentity; 
using SsoOkta;
using SsoOkta.App_Start;
using SsoOkta.Models.UmbracoIdentity;
using Umbraco.Core.Services;

[assembly: OwinStartup("UmbracoIdentityStartup", typeof(UmbracoIdentityOwinStartup))]
namespace SsoOkta
{

    /// <summary>
    /// OWIN Startup class for UmbracoIdentity 
    /// </summary>
    public class UmbracoIdentityOwinStartup : UmbracoIdentityOwinStartupBase
    {
        protected override void ConfigureServices(IAppBuilder app, ServiceContext services)
        {
            IdentityModelEventSource.ShowPII = true;
            app.Use(async (owinContext, next) => {
                if (owinContext.Request.Scheme != "https"
                    && owinContext.Request.Headers.TryGetValue("X-Forwarded-Proto", out var headerVals)
                    && headerVals.Length > 0
                    && headerVals[0] == "https")
                {
                    // setting the scheme to "https" is how IsSecure returns true
                    owinContext.Request.Scheme = headerVals[0];
                }

                await next.Invoke();
            });
            base.ConfigureServices(app, services);
        }
        protected override void ConfigureUmbracoUserManager(IAppBuilder app)
        {
            base.ConfigureUmbracoUserManager(app);

            //Single method to configure the Identity user manager for use with Umbraco
            app.ConfigureUserManagerForUmbracoMembers<UmbracoApplicationMember>();

            //Single method to configure the Identity user manager for use with Umbraco
            app.ConfigureRoleManagerForUmbracoMembers<UmbracoApplicationRole>();
        }

        protected override void ConfigureUmbracoAuthentication(IAppBuilder app)
        {
            base.ConfigureUmbracoAuthentication(app);

            // Enable the application to use a cookie to store information for the 
            // signed in user and to use a cookie to temporarily store information 
            // about a user logging in with a third party login provider 
            // Configure the sign in cookie
            
            var cookieOptions = CreateFrontEndCookieAuthenticationOptions();

            // You can change the cookie options here. The cookie options will be automatically set
            // based on what is configured in the security section of umbracoSettings.config and the web.config.
            // For example:
            // cookieOptions.CookieName = "testing";
            // cookieOptions.ExpireTimeSpan = TimeSpan.FromDays(20);

            cookieOptions.Provider = new CookieAuthenticationProvider
            {
                // Enables the application to validate the security stamp when the user 
                // logs in. This is a security feature which is used when you 
                // change a password or add an external login to your account.  
                OnValidateIdentity = SecurityStampValidator
                        .OnValidateIdentity<UmbracoMembersUserManager<UmbracoApplicationMember>, UmbracoApplicationMember, int>(
                            TimeSpan.FromMinutes(30),
                            (manager, user) => user.GenerateUserIdentityAsync(manager),
                            identity => identity.GetUserId<int>())
            };

            app.UseCookieAuthentication(cookieOptions, PipelineStage.Authenticate);

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseIdentityServerForUserAuthentication();
            app.UseIdentityServerForMemberAuthentication();
        }
    }
}

