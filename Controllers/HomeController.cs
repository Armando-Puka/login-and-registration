using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using LoginAndRegistration.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.AspNetCore.Mvc.Filters;

namespace LoginAndRegistration.Controllers;

public class SessionCheckAttribute : ActionFilterAttribute {
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        int? userId = context.HttpContext.Session.GetInt32("UserId");
        if (userId == null) {
            context.Result = new RedirectToActionResult("Auth", "Home", null);
        }
    }
}
public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private MyContext _context; 

    public HomeController(ILogger<HomeController> logger, MyContext context)
    {
        _logger = logger;
        _context = context;
    }

    [SessionCheck]
    public IActionResult Index()
    {
        return View();
    }

    [HttpGet("Auth")]
    public IActionResult Auth() {
        return View();
    }

    [HttpPost("Register")]
    public IActionResult Register(User userFromForm) {
        if (ModelState.IsValid) {
            PasswordHasher<User> Hasher = new PasswordHasher<User>();
            userFromForm.Password = Hasher.HashPassword(userFromForm, userFromForm.Password);
            _context.Add(userFromForm);
            _context.SaveChanges();

            return RedirectToAction("Auth");
        }
        return View("Auth");
    }

    [HttpPost("Login")]
    public IActionResult Login(LoginUser registeredUser) {
        if (ModelState.IsValid) {
            User userFromDb = _context.Users.FirstOrDefault(e => e.Email == registeredUser.LoginEmail);

            if (userFromDb == null) {
                ModelState.AddModelError("LoginEmail", "Invalid email address.");
                return View("Auth");
            }

            PasswordHasher<LoginUser> Hasher = new PasswordHasher<LoginUser>();
            
            var result = Hasher.VerifyHashedPassword(registeredUser, userFromDb.Password, registeredUser.LoginPassword);

            if (result == 0) {
                ModelState.AddModelError("LoginPassword", "Invalid password.");
                return View("Auth");
            }

            HttpContext.Session.SetInt32("UserId", userFromDb.UserId);
            return View("Index");
        }

        return View("Auth");
    }

    [HttpGet("Logout")]
    public IActionResult Logout() {
        HttpContext.Session.Clear();
        return RedirectToAction("Auth");
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
