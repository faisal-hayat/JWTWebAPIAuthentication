using JwtWebAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;      
        }

        #region Register
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto userDto)
        {
            CreatePasswordHash(userDto.Passowrd, out byte[] passwordHash, out byte[] passwordSalt);
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.Username = userDto.UserName;
            return Ok(user);
        }
        #endregion

        #region Login
        [HttpPost("Login")]
        public async Task<ActionResult<string>> Login(UserDto userRequest)
        {
            if (user.Username != userRequest.UserName)
            {
                return BadRequest("Something went wrong !");
            }
            else
            {
                // this is where we will be placing the main logic
                if (!VerifyPasswordHash(userRequest.Passowrd, user.PasswordHash, user.PasswordSalt))
                {
                    // if user has not provided correct password
                    return BadRequest("Something went wrong, plsease provide correct username and password");
                }
                else
                {
                    var token = CreateToken(user);
                    return Ok(token);
                }
            }
        }
        #endregion

        #region create passwords hash
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using ( var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }
        #endregion


        #region verify password hash
        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(user.PasswordSalt))
            {
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computeHash.SequenceEqual(passwordHash);
            }
        }
        #endregion

        #region Create Token
        private string CreateToken(User userRequest)
        {
            List<Claim> claims = new List<Claim> { 
                new Claim(ClaimTypes.Name, userRequest.Username),
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            var credential = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            // define payload of json web token
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credential
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
        #endregion

    }
}
