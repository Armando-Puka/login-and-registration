#pragma warning disable CS8618
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace LoginAndRegistration.Models;

public class User {
    [Key]
    public int UserId { get; set; }

    [Required(ErrorMessage = "Name is required.")]
    [MinLength(2, ErrorMessage = "Name must be at least 2 characters.")]
    public string Name { get; set; }

    [Required(ErrorMessage = "Last Name is required.")]
    [MinLength(2, ErrorMessage = "Last Name must be at least 2 characters.")]
    public string LastName { get; set; }

    [Required]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$", ErrorMessage = "Invalid email address.")]
    [UniqueEmail]
    public string Email { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters.")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W)[\w\d\W]{8,}$", ErrorMessage = "Password must include at least one lowercase letter, one uppercase letter, one digit, and one special character.")]
    public string Password { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime UpdatedAt { get; set; } = DateTime.Now;

    [NotMapped]
    [Required(ErrorMessage = "Confirm Password is required.")]
    [Compare("Password")]
    [DataType(DataType.Password)]
    public string PasswordConfirm { get; set; }
}