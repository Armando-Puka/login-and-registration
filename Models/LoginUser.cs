#pragma warning disable CS8618
using System.ComponentModel.DataAnnotations;
namespace LoginAndRegistration.Models;

public class LoginUser {
    [Required(ErrorMessage = "Email address is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    public string LoginEmail { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    public string LoginPassword { get; set; }
}