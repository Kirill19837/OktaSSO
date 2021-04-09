using SsoOkta.Contracts;
using SsoOkta.Services;
using Umbraco.Core;
using Umbraco.Core.Composing;
using Umbraco.Core.Models.Sections;
using Umbraco.Web;

namespace SsoOkta.Composers
{
    public class ServicesComposer : IUserComposer
    {
        public void Compose(Composition composition)
        {
            composition.Register<ISsoService, OktaService>();
        }
    }

}
