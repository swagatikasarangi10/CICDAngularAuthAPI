using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using AngularAuthAPI.Models.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext authContext)
        {
            _authContext = authContext;
        }
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
            {
                return BadRequest();
            }
             var user=await _authContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName );
            if (user == null)
            {
                return NotFound(new { Message = "User Not Found!" });
                
            }
            if(!PasswordHasher.VerifyPassword(userObj.Password,user.Password))
            {
                return BadRequest(new
                {
                    Message = "Password is Incorrect"
                }) ;
            }
            userObj.Role = user.Role;
            user.Token = CreateJwt(user);
            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(5);
            await _authContext.SaveChangesAsync();

            //return Ok(new
            //{
            //    Token= user.Token,
            //    Message = "Login Success!"
            //});
            return Ok(new TokenApiDto
            {
                AccessToken=newAccessToken,
                RefreshToken=newRefreshToken

            });
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if(userObj == null)
            {
                return BadRequest();
            }
            if( await CheckuserNameExistAsync(userObj.UserName))
            {
                return BadRequest(new
                {
                    Message="username already exists!"
                });
            }
            if (await CheckEmailExistAsync(userObj.Email))
            {
                return BadRequest(new
                {
                    Message = "email already exists!"
                });
            }
            userObj.Password= PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
             await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                Message="User Registered!"
            });

                

        }
        private  async Task<bool> CheckuserNameExistAsync(string username)
        {
            return await _authContext.Users.AnyAsync(x => x.UserName == username);
        }
        private async Task<bool> CheckEmailExistAsync(string email)
        {
            return await _authContext.Users.AnyAsync(x => x.Email == email);
        }
        private string CheckpasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if(password.Length < 8)
            {
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            }
            if(!(Regex.IsMatch(password, "^[a-zA-Z0-9_]*$")))
            {
                sb.Append("password should be alpha numeric" + Environment.NewLine);
            }
            return sb.ToString();
        }
        private string CreateJwt(User userObj)// token consists header, payload,signature// payload willl have fullname and role
        {
            //1. jwt security handler
            JwtSecurityTokenHandler securityTokenHandler = new JwtSecurityTokenHandler();
            var result = "";
            try
            {


                
                //2. create a key
                var key = Encoding.UTF8.GetBytes("veryverysecret.....");
                //3. identity for payload
                var identity = new ClaimsIdentity(new Claim[]
                    { new Claim(ClaimTypes.Role,userObj.Role),
                new Claim(ClaimTypes.Name,userObj.UserName)

                });
                //4.credentials
                var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
                //5. descriptor
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = identity,
                    Expires = DateTime.Now.AddSeconds(60),
                    SigningCredentials = credentials
                };
                var token = securityTokenHandler.CreateToken(tokenDescriptor);
                result = securityTokenHandler.WriteToken(token);


            }
            catch(Exception ex)
            {
                var message = ex.ToString();
            }
            return result;//securityTokenHandler.WriteToken(token);
        }
        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);
            var tokenInUser = _authContext.Users.Any(x=> x.RefreshToken == refreshToken);
            if(tokenInUser)
            {
                CreateRefreshToken();
            }
                
            return refreshToken;
        }
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryverysecret.....");
            var tokenValidationParameter = new TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false

            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken security;
            var principal= tokenHandler.ValidateToken(token,tokenValidationParameter, out security);
            var jwtSecurityToken = security as JwtSecurityToken;
            if(jwtSecurityToken != null && !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid Security Token!");
            }
            return principal;
        }
        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if(tokenApiDto == null)
            {
                return BadRequest("invalid client request");
            }
            string accessToken= tokenApiDto.AccessToken;
            string refreshToken= tokenApiDto.RefreshToken;
            var principal = GetPrincipalFromExpiredToken(accessToken);
            var userName = principal.Identity.Name;
            var user= _authContext.Users.FirstOrDefault(u=>u.UserName == userName);
            if(user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now) {
                return BadRequest(
                    "invalid request"
                    );
            }
            var newAccessToken = CreateJwt(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDto
            {
                AccessToken= newAccessToken,
                RefreshToken=newRefreshToken,
            });
        }

    }
}
