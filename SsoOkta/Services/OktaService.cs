using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Okta.Sdk;
using Okta.Sdk.Configuration;
using SsoOkta.App_Start;
using SsoOkta.Contracts;
using Umbraco.Web.Models;

namespace SsoOkta.Services
{
    public class OktaService : ISsoService
    {
        IOktaClient _oktaClient;
        public OktaService()
        {
            _oktaClient = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = OidcConfiguration.Authority,
                Token = OidcConfiguration.ApiToken
            });
        }

        public async Task<bool> ApplyMember(string email)
        {
            var user = await _oktaClient.Users.GetUserAsync(email);
            if (user == null) return false;
            var group = await _oktaClient.Groups.FirstOrDefaultAsync(x => x.Profile.Name == OidcConfiguration.Cms.MembersGroup);
            // add the user to the group by using their id's
            if (group != null && user != null)
            {   
                await user.AddToGroupAsync(group.Id); //also assign user to group application 
                return true;
            }
            return false;
        }

        public async Task<IdentityResult> CreateMember(RegisterModel memberData)
        {
            try
            {
                var user = await _oktaClient.Users.CreateUserAsync(new CreateUserWithPasswordOptions
                {
                    // User profile object
                    Profile = new UserProfile
                    {
                        DisplayName = memberData.Name,
                        FirstName = memberData.MemberProperties.FirstOrDefault(p => string.Equals(p.Alias, "firstname", StringComparison.OrdinalIgnoreCase))?.Value,
                        LastName = memberData.MemberProperties.FirstOrDefault(p => string.Equals(p.Alias, "lastname", StringComparison.OrdinalIgnoreCase))?.Value,
                        PrimaryPhone = memberData.MemberProperties.FirstOrDefault(p => string.Equals(p.Alias, "phone", StringComparison.OrdinalIgnoreCase))?.Value,
                        Email = memberData.Email,
                        Login = memberData.Email,
                    },
                    Password = memberData.Password,
                    Activate = false,
                });
            }
            catch (OktaApiException ex)
            {
                return new IdentityResult($"{ex.Message}");
            }
            catch (Exception ex)
            {
                return new IdentityResult($"{ex.Message}");
            }
            return IdentityResult.Success;
        }
        public async Task<bool> ActivateMember(string email)
        {
            var user = await _oktaClient.Users.GetUserAsync(email);
            if (user == null) return false;
            await user.ActivateAsync();
            return true;
        }

        public async Task<bool> MemberExists(string email)
        {
            try
            {
                var user = await _oktaClient.Users.GetUserAsync(email);
                return user != null;
            }
            catch (OktaApiException ex)
            {
                // hangle api exception
                if (ex.StatusCode == 404)
                    return false;
                //handle additional problems if needed
                return false;
            }
            catch (Exception ex)
            {
                //log generall errors
                return false;
            }
        }
    }
}
