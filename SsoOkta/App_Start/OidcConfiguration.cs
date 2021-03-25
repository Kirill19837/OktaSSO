using System.Configuration;

namespace SsoOkta.App_Start
{
    public static class OidcConfiguration
    {
        public static string Authority => ConfigurationManager.AppSettings.Get("oidc:authority");

        public static class Cms
        {
            public static string ClientId => ConfigurationManager.AppSettings.Get("oidc:front:clientId");
            public static string ClientSecret => ConfigurationManager.AppSettings.Get("oidc:front:clientSecret");
            public static string PostLogoutUris => ConfigurationManager.AppSettings.Get("oidc:front:postLogoutUris");
            public static string RedirectUris => ConfigurationManager.AppSettings.Get("oidc:front:redirectUris");
        }

        public static class Backoffice
        {
            public static string ClientId => ConfigurationManager.AppSettings.Get("oidc:backoffice:clientId");
            public static string ClientSecret => ConfigurationManager.AppSettings.Get("oidc:backoffice:clientSecret");
            public static string PostLogoutUris => ConfigurationManager.AppSettings.Get("oidc:backoffice:postLogoutUris");
            public static string RedirectUris => ConfigurationManager.AppSettings.Get("oidc:backoffice:redirectUris");
        }
    }
}