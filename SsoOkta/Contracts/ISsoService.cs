using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Umbraco.Core.Models;
using Umbraco.Web.Models;

namespace SsoOkta.Contracts
{
	public interface ISsoService
	{
		/// <summary>
		/// Check if member with specified email exists
		/// </summary>
		/// <param name="email">Email</param>
		/// <returns>bool indicating if user exists</returns>
		Task<bool> MemberExists(string email);

		/// <summary>
		/// Activate member
		/// </summary>
		/// <param name="email">user email</param>
		/// <returns></returns>
		Task<bool> ActivateMember(string email);

		/// <summary>
		/// Creates new member
		/// </summary>
		/// <param name="memberData">Member data</param>
		/// <returns>IMember created</returns>
		Task<IdentityResult> CreateMember(RegisterModel memberData);

		/// <summary>
		/// Apply application and group to member if it is already exists
		/// </summary>
		/// <param name="memberData">Member data</param>
		/// <returns>IMember created</returns>
		Task<bool> ApplyMember(string email);
	}
}