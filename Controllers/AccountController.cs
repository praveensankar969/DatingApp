using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using API.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenInterface _tokenService;
        public AccountController(DataContext context, ITokenInterface _tokenService)
        {
            this._tokenService = _tokenService;
            this._context = context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDTO>> Register(RegisterDTO register)
        {
            using var hmac = new HMACSHA256();
            if (await (CheckUserName(register.UserName)))
            {
                return BadRequest("Username already present");
            }

            var user = new AppUser
            {
                UserName = register.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(register.Password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
             return new UserDTO
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> Login(LoginDTO login)
        {
            var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == login.UserName);
            if (user == null)
            {
                return BadRequest("Invalid username");
            }
            using var hmac = new HMACSHA256(user.PasswordSalt);
            var loginPasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(login.Password));
            for (int i = 0; i < user.PasswordHash.Length; i++)
            {
                if (user.PasswordHash[i] != loginPasswordHash[i]) return BadRequest("Wrong password");
            }

            return new UserDTO
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };

        }
        private async Task<bool> CheckUserName(string userName)
        {
            return await _context.Users.AnyAsync(u => u.UserName == userName.ToLower());
        }
    }
}