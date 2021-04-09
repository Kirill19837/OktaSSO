using System;
using System.Web;
using System.Web.Http;
using Microsoft.Owin;
using Umbraco.Core;
using Umbraco.Core.Composing;
using Umbraco.Web.Security;

namespace SsoOkta.App_Start
{

    public class BackofficeLogoutComposer : IUserComposer
    {
        public void Compose(Composition composition)
        {
            composition.Components().Append<BackofficeLogoutComponent>();
        }
    }

    public class BackofficeLogoutComponent : IComponent
    {

        public void Initialize()
        {
            BackOfficeUserManager.LogoutSuccess += BackOfficeUserManagerOnLogoutSuccess;
        }

        private void BackOfficeUserManagerOnLogoutSuccess(object sender, EventArgs e)
        {
            new HttpContextWrapper(HttpContext.Current).UmbracoLogout();
            var accesCookie = new HttpCookie("access_token");
            var accesRefreshCookie = new HttpCookie("refresh_token"); 
            accesCookie.Expires = DateTime.Now.AddDays(-1);
            accesRefreshCookie.Expires = DateTime.Now.AddDays(-1);
            HttpContext.Current.Response.Cookies.Add(accesCookie);
            HttpContext.Current.Response.Cookies.Add(accesRefreshCookie);
        }

        public void Terminate()
        {
            BackOfficeUserManager.LogoutSuccess -= BackOfficeUserManagerOnLogoutSuccess;
        }
    }
}