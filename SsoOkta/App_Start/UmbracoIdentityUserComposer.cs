using Microsoft.AspNet.Identity.Owin;
using System.Web;
using Umbraco.Core;
using Umbraco.Core.Composing;
using Umbraco.Web;
using UmbracoIdentity;
using SsoOkta.Models.UmbracoIdentity;

namespace SsoOkta
{
    /// <summary>
    /// Registers the UmbracoIdentity user manager and role manager into the DI Container
    /// </summary>
    [RuntimeLevel(MinLevel = RuntimeLevel.Run)]
    public class UmbracoIdentityUserComposer : IUserComposer
    {
        public void Compose(Composition composition)
        {
            composition.Register(x =>
            {
                //needs to resolve from Owin
                var owinCtx = x.GetInstance<IHttpContextAccessor>().HttpContext.GetOwinContext();
                return owinCtx.GetUserManager<UmbracoMembersUserManager<UmbracoApplicationMember>>();
            }, Lifetime.Request);

            composition.Register(x =>
            {
                //needs to resolve from Owin
                var owinCtx = x.GetInstance<IHttpContextAccessor>().HttpContext.GetOwinContext();
                return owinCtx.GetUserManager<UmbracoMembersRoleManager<UmbracoApplicationRole>>();
            }, Lifetime.Request);
        }

    }
}
