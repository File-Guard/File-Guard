using Aspose.Email;
using Aspose.Email.Clients;
using Aspose.Email.Clients.Smtp;
using ChatGurd.DTO;
using ChatGurd.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static System.Net.WebRequestMethods;

namespace ChatGurd.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class MainController : ControllerBase
	{

		private readonly HabeebTaskContext _context;
		private readonly IHubContext<SingleHub> _hubContext;
		public MainController(HabeebTaskContext context, IHubContext<SingleHub> hubContext)
		{
			this._context = context;
			this._hubContext = hubContext;
		}

		//Sub Method (Method Will Used To Help Another method in main target )
		public int DecodeToken(string tokenString)
		{
			String toke = "Bearer " + tokenString;
			var jwtEncodedString = toke.Substring(7);

			var token = new JwtSecurityToken(jwtEncodedString: jwtEncodedString);
			int roleId = Int32.Parse((token.Claims.First(c => c.Type == "UserId").Value.ToString()));
			return roleId;
		}
		static string GetMd5Hash(MD5 md5Hash, string input)
		{
			// Convert the input string to a byte array and compute the hash.
			byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
			StringBuilder sBuilder = new StringBuilder();
			for (int i = 0; i < data.Length; i++)
			{
				sBuilder.Append(data[i].ToString("x2"));
			}
			return sBuilder.ToString();
		}

		public string Encrypt5TimesUsingMD5Hash(string input)
		{
			using (MD5 md5Hash = MD5.Create())
			{
				return GetMd5Hash(md5Hash, GetMd5Hash(md5Hash, GetMd5Hash(md5Hash, GetMd5Hash(md5Hash, GetMd5Hash(md5Hash, GetMd5Hash(md5Hash, input))))));

			}
		}

		static string EncryptPassword(string text)
		{
			string encText = "";
			char[] chars = text.ToCharArray();
			for (int i = 0; i < text.Length; i++)
			{

				int temp = (int)chars[i] + (int)new Random().Next(11);
				chars[i] = (char)temp;
			}

			foreach (char c in chars)
			{
				encText += c;
			}

			return encText;
		}

		public string GenerateJwtToken(Auth loginCredinital)
		{
			var tokenHandler = new JwtSecurityTokenHandler();
			var tokenKey = Encoding.UTF8.GetBytes("LongSecrectStringForModulekodestartppopopopsdfjnshbvhueFGDKJSFBYJDSAGVYKDSGKFUYDGASYGFskc vhHJVCBYHVSKDGHASVBCL");
			var tokenDescriptior = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(new Claim[]
				{
						new Claim(ClaimTypes.Email,loginCredinital.Email),
						new Claim("UserId",loginCredinital.UserId+""),
						new Claim("Activation",loginCredinital.IsActive+"")
				}),
				Expires = DateTime.Now.AddHours(2),
				SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey)
				, SecurityAlgorithms.HmacSha256Signature)
			};
			var token = tokenHandler.CreateToken(tokenDescriptior);
			return tokenHandler.WriteToken(token);
		}



		//Add New User (Register)
		[HttpPost]
		[Route("[action]")]
		public async Task<IActionResult> CreateNewAccounts([FromBody] RegistrationDTO registration)
		{
			var us = _context.Users.Where(x => x.Email == registration.Email ||
			x.UserName == registration.UserName).SingleOrDefault();
			if (us == null)
			{
				User chatGurdUser = new User();
				chatGurdUser.FullName = registration.FullName;
				chatGurdUser.UserName = registration.UserName;
				chatGurdUser.BirthDate = registration.BirthDate;
				chatGurdUser.Email = registration.Email;
				chatGurdUser.Phone = registration.Phone;
				chatGurdUser.ProfileImage = registration.ProfileImage;
				await _context.Users.AddAsync(chatGurdUser);
				await _context.SaveChangesAsync();

				Auth auth = new Auth();

				auth.Email = Encrypt5TimesUsingMD5Hash(registration.Email) + EncryptPassword("Text");
				auth.Password = Encrypt5TimesUsingMD5Hash(registration.Password) + EncryptPassword("Text");
				auth.IsActive = true;
				auth.UserId = _context.Users.OrderByDescending(x => x.UserId).First().UserId;
				await _context.AddAsync(auth);
				await _context.SaveChangesAsync();

				//Verification verification = new Verification();
				//verification.Email = registration.Email;
				//verification.Code = new Random().Next(999999) + "";

				//_context.Add(verification);
				//_context.SaveChanges();
				return Ok(true);
			}
			else
			{
				return BadRequest("User In Use by another human");
			}

		}
		//Login 
		[HttpPost]
		[Route("[action]")]
		public async Task<IActionResult> AccessAccount([FromBody] LoginDTO loginDTO)
		{
			string orgMail = loginDTO.Email;
			loginDTO.Email = Encrypt5TimesUsingMD5Hash(loginDTO.Email);
			loginDTO.Password = Encrypt5TimesUsingMD5Hash(loginDTO.Password);
			if (loginDTO.Password != null && loginDTO.Email != null)
			{
				var loginCredinital = _context.Auths.Where(x => x.Password.Substring(0, 32).Equals(loginDTO.Password)
				&& x.Email.Substring(0, 32).Equals(loginDTO.Email) && x.IsActive == true
				).SingleOrDefault();
				if (loginCredinital != null)
				{
					loginCredinital.LastLog = DateTime.Now;
					_context.Update(loginCredinital);
					_context.SaveChanges();
					Random random = new Random();
					int code = random.Next(111111, 999999);
					Verification verification = new Verification();
					verification.Email = orgMail;
					verification.Code = code.ToString();

					await _context.AddAsync(verification);
					await _context.SaveChangesAsync();

					SendOtpViaEmail(verification.Code, verification.Email);

					return Ok(GenerateJwtToken(loginCredinital));
				}
				return Unauthorized();
			}
			else
			{
				return BadRequest(false);
			}
		}
		[HttpPost]
		[Route("[action]")]
		public async Task<IActionResult> CheckCode([FromBody] Class CodeDTO)
		{
			var verific = _context.Verifications.Where(x => x.Code == CodeDTO.Code).FirstOrDefault();
			if (verific != null)
			{
				return Ok("Done");
			}
			throw new Exception("Something Went Wrong");
		}
		[NonAction]
		void SendOtpViaEmail(string code, string email)
		{
			// Create a new instance of MailMessage class
			MailMessage message = new MailMessage();

			// Set subject of the message, body and sender information
			message.Subject = "File Guard Verficiation Code";
			message.Body = "Use this Following Code  \n " + code + "\nto Confirm Your Opertaion Kindly Remindrer it's valid for 10 minutes since now";
			message.From = new MailAddress("Pcoding3@outlook.com", "File Guard", false);
			// Add To recipients and CC recipients
			message.To.Add(new MailAddress(email, "Recipient 1", false));

			// Create an instance of SmtpClient class
			SmtpClient client = new SmtpClient();

			// Specify your mailing Host, Username, Password, Port # and Security option
			client.Host = "smtp.office365.com";
			client.Username = "Pcoding3@outlook.com";
			client.Password = "152Bisho@2023";
			client.Port = 587;
			client.SecurityOptions = SecurityOptions.SSLExplicit;
			try
			{
				// Send this email
				client.Send(message);
			}
			catch (Exception ex)
			{
				Trace.WriteLine(ex.ToString());
			}


		}

		[HttpPost]
		[Route("[action]")]
		public async Task<IActionResult> SaveNewFile(FileDTO fileDTO)
		{
			//fileDTO.file= await encFile(fileDTO.file);
			Models.File file = new Models.File();
			file.ContentDescription = fileDTO.content;
			byte[] encrypted;
			using (Aes aes = Aes.Create())
			{
				encrypted = EncryptStringToBytes(fileDTO.file, aes.Key, aes.IV);
				file.Base64Code = encrypted;
				file.Key = aes.Key;
				file.Iv = aes.IV;
				//file.Base64Code = 

			}

			int userId = DecodeToken(fileDTO.token);
			file.UserId = userId;
			file.Extension = fileDTO.extension;
			await _context.AddAsync(file);
			await _context.SaveChangesAsync();
			return Ok("Saved");
		}
		[HttpGet]
		[Route("[action]")]
		public async Task<IActionResult> GetFileByUserId([FromQuery] string token)
		{
			int userId = DecodeToken(token);
			var user = _context.Users.Where(u => u.UserId == userId).FirstOrDefault();
			if (user != null)
			{
				var myfiles = _context.Files.Where(x => x.UserId == userId).ToList();

				foreach (var file in myfiles)
				{
					using (Aes aes = Aes.Create())
					{
						file.ExecutFile = await DecryptStringFromBytes(file.Base64Code, file.Key, file.Iv);
					}
				}
				return Ok(myfiles);
			}
			return BadRequest("No Such User");

		}
		[HttpGet]
		[Route("[action]")]
		public IActionResult DeleteExistiFile(int fileId)
		{
			var file = _context.Files.Where(f => f.FileId == fileId).FirstOrDefault();
			if (file != null)
			{
				_context.Files.Remove(file);
				_context.SaveChanges();
				return Ok("Deleted");
			}
			return BadRequest("No Such User");
		}
		[HttpGet]
		[Route("[action]")]
		public async Task<IActionResult> CloseSystem([FromQuery] string email)
		{
			var loginCredinital = _context.Auths.Where(x =>
				x.Email.Equals(email) && x.IsActive == true
				).SingleOrDefault();
			if (loginCredinital != null)
			{
				loginCredinital.LastOut = DateTime.Now;
				_context.Update(loginCredinital);
				await _context.SaveChangesAsync();
				return Ok(true);
			}
			else
			{
				return Unauthorized(false);
			}
		}
		[NonAction]
		static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
		{
			byte[] encrypted;

			// Create an Aes object with the specified key and IV.
			using (Aes aes = Aes.Create())
			{
				aes.Key = key;
				aes.IV = iv;

				// Create a new MemoryStream object to contain the encrypted bytes.
				using (MemoryStream memoryStream = new MemoryStream())
				{
					// Create a CryptoStream object to perform the encryption.
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
					{
						// Encrypt the plaintext.
						using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
						{
							streamWriter.Write(plainText);
						}

						encrypted = memoryStream.ToArray();
					}
				}
			}

			return encrypted;
		}
		[NonAction]
		static async Task<string> DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
		{
			string decrypted;

			// Create an Aes object with the specified key and IV.
			using (Aes aes = Aes.Create())
			{
				aes.Key = key;
				aes.IV = iv;

				// Create a new MemoryStream object to contain the decrypted bytes.
				using (MemoryStream memoryStream = new MemoryStream(cipherText))
				{
					// Create a CryptoStream object to perform the decryption.
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
					{
						// Decrypt the ciphertext.
						using (StreamReader streamReader = new StreamReader(cryptoStream))
						{
							//cryptoStream.FlushFinalBlock();
							decrypted = streamReader.ReadToEnd();
						}
					}
				}
			}

			return decrypted;
		}
	}
}
