
using JWTAuthServer.Data;
using JWTAuthServer.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;

namespace JWTAuthServer
{
    //public class Program
    //{
    //    public static void Main(string[] args)
    //    {
    //        var builder = WebApplication.CreateBuilder(args);
    //        // Add controller services to the container and configure JSON serialization options
    //        builder.Services.AddControllers()
    //            .AddJsonOptions(options =>
    //            {
    //                // Preserve property names as defined in the C# models (disable camelCase naming)
    //                options.JsonSerializerOptions.PropertyNamingPolicy = null;
    //            });
    //        // Add services for generating Swagger/OpenAPI documentation
    //        builder.Services.AddEndpointsApiExplorer();
    //        builder.Services.AddSwaggerGen();
    //        // Configure Entity Framework Core with SQL Server using the connection string from configuration
    //        builder.Services.AddDbContext<ApplicationDbContext>(options =>
    //            options.UseSqlServer(builder.Configuration.GetConnectionString("EFCoreDBConnection")));
    //        // Register the KeyRotationService as a hosted (background) service
    //        // This service handles periodic rotation of signing keys to enhance security
    //        builder.Services.AddHostedService<KeyRotationService>();
    //        // Configure Authentication using JWT Bearer tokens
    //        builder.Services.AddAuthentication(options =>
    //        {
    //            // This indicates the authentication scheme that will be used by default when the app attempts to authenticate a user.
    //            // Which authentication handler to use for verifying who the user is by default.
    //            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    //            // This indicates the authentication scheme that will be used by default when the app encounters an authentication challenge. 
    //            // Which authentication handler to use for responding to failed authentication or authorization attempts.
    //            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    //        })
    //        .AddJwtBearer(options =>
    //        {
    //            // Define token validation parameters to ensure tokens are valid and trustworthy
    //            options.TokenValidationParameters = new TokenValidationParameters
    //            {
    //                ValidateIssuer = true, // Ensure the token was issued by a trusted issuer
    //                ValidIssuer = builder.Configuration["Jwt:Issuer"], // The expected issuer value from configuration
    //                ValidateAudience = false, // Disable audience validation (can be enabled as needed)
    //                ValidateLifetime = true, // Ensure the token has not expired
    //                ValidateIssuerSigningKey = true, // Ensure the token's signing key is valid
    //                // Define a custom IssuerSigningKeyResolver to dynamically retrieve signing keys from the JWKS endpoint
    //                IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
    //                {
    //                    //Console.WriteLine($"Received Token: {token}");
    //                    //Console.WriteLine($"Token Issuer: {securityToken.Issuer}");
    //                    //Console.WriteLine($"Key ID: {kid}");
    //                    //Console.WriteLine($"Validate Lifetime: {parameters.ValidateLifetime}");
    //                    // Initialize an HttpClient instance for fetching the JWKS
    //                    var httpClient = new HttpClient();
    //                    // Synchronously fetch the JWKS (JSON Web Key Set) from the specified URL
    //                    var jwks = httpClient.GetStringAsync($"{builder.Configuration["Jwt:Issuer"]}/.well-known/jwks.json").Result;
    //                    // Parse the fetched JWKS into a JsonWebKeySet object
    //                    var keys = new JsonWebKeySet(jwks);
    //                    // Return the collection of JsonWebKey objects for token validation
    //                    return keys.Keys;
    //                }
    //            };
    //        });
    //        // Build the WebApplication instance based on the configured services and middleware
    //        var app = builder.Build();
    //        // Enable Swagger middleware only in the development environment for API documentation and testing
    //        if (app.Environment.IsDevelopment())
    //        {
    //            app.UseSwagger(); // Generates the Swagger JSON document
    //            app.UseSwaggerUI(); // Enables the Swagger UI for interactive API exploration
    //        }
    //        // Enforce HTTPS redirection to ensure secure communication
    //        app.UseHttpsRedirection();
    //        // Enable Authentication middleware to process and validate incoming JWT tokens
    //        app.UseAuthentication();
    //        // Enable Authorization middleware to enforce access policies based on user roles and claims
    //        app.UseAuthorization();
    //        app.MapControllers();
    //        app.Run();
    //    }
    //}
    //public class Program
    //{
    //    public static void Main(string[] args)
    //    {
    //        var builder = WebApplication.CreateBuilder(args);
    //        // Add services to the container.
    //        builder.Services.AddControllers()
    //        .AddJsonOptions(options =>
    //        {
    //            // This will use the property names as defined in the C# model
    //            options.JsonSerializerOptions.PropertyNamingPolicy = null;
    //        });
    //        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    //        builder.Services.AddEndpointsApiExplorer();
    //        builder.Services.AddSwaggerGen();
    //        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    //        .AddJwtBearer(options =>
    //        {
    //            options.TokenValidationParameters = new TokenValidationParameters
    //            {
    //                ValidateIssuer = true,
    //                ValidIssuer = builder.Configuration["Jwt:Issuer"],
    //                ValidateAudience = false,
    //                ValidateLifetime = true,
    //                ValidateIssuerSigningKey = true,
    //                IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
    //                {
    //                    var httpClient = new HttpClient();
    //                    var jwks = httpClient.GetStringAsync(builder.Configuration["Jwt:JWKS"]).Result;
    //                    var keys = new JsonWebKeySet(jwks).Keys;
    //                    return keys;
    //                }
    //            };
    //        });
    //        var app = builder.Build();
    //        // Configure the HTTP request pipeline.
    //        if (app.Environment.IsDevelopment())
    //        {
    //            app.UseSwagger();
    //            app.UseSwaggerUI();
    //        }
    //        app.UseHttpsRedirection();
    //        app.UseAuthentication();
    //        app.UseAuthorization();
    //        app.MapControllers();
    //        app.Run();
    //    }
    //}

    public class Program
    {
        // Configuration settings
        private static readonly string AuthServerBaseUrl = "https://localhost:7022"; // Authentication Server URL
        private static readonly string ResourceServerBaseUrl = "https://localhost:7267"; // Replace with your Resource Server's URL and port
        private static readonly string ClientId = "Client1"; // Must match a valid ClientId in Auth Server
        private static readonly string UserEmail = "pranaya@example.com"; // Replace with registered user's email
        private static readonly string UserPassword = "Password@123"; // Replace with registered user's password
        static async Task Main(string[] args)
        {
            try
            {
                // Step 1: Authenticate and obtain JWT token
                var token = await AuthenticateAsync(UserEmail, UserPassword, ClientId);
                if (string.IsNullOrEmpty(token))
                {
                    Console.WriteLine("Authentication failed. Exiting...");
                    return;
                }
                Console.WriteLine("Authentication successful. JWT Token obtained.\n");
                // Step 2: Consume Resource Server's ProductsController endpoints
                await ConsumeResourceServerAsync(token);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }
        // Authenticates the user with the Authentication Server and retrieves a JWT token.
        private static async Task<string?> AuthenticateAsync(string email, string password, string clientId)
        {
            using var httpClient = new HttpClient();
            var loginUrl = $"{AuthServerBaseUrl}/api/Auth/Login";
            var loginData = new
            {
                Email = email,
                Password = password,
                ClientId = clientId
            };
            var content = new StringContent(JsonSerializer.Serialize(loginData), Encoding.UTF8, "application/json");
            Console.WriteLine("Sending authentication request...");
            var response = await httpClient.PostAsync(loginUrl, content);
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"Authentication failed with status code: {response.StatusCode}");
                var errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Error: {errorContent}\n");
                return null;
            }
            var responseContent = await response.Content.ReadAsStringAsync();
            var jsonDoc = JsonDocument.Parse(responseContent);
            if (jsonDoc.RootElement.TryGetProperty("Token", out var tokenElement))
            {
                return tokenElement.GetString();
            }
            Console.WriteLine("Token not found in the authentication response.\n");
            return null;
        }
        // Consumes the Resource Server's ProductsController endpoints using the JWT token.
        private static async Task ConsumeResourceServerAsync(string token)
        {
            using var httpClient = new HttpClient();
            // Set the Authorization header with the Bearer token
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            // Create a new product
            var newProduct = new
            {
                Name = "Smartphone",
                Description = "A high-end smartphone with excellent features.",
                Price = 999.99
            };
            Console.WriteLine("Creating a new product...");
            var createResponse = await httpClient.PostAsync(
                $"{ResourceServerBaseUrl}/api/Products/Add",
                new StringContent(JsonSerializer.Serialize(newProduct), Encoding.UTF8, "application/json"));
            if (createResponse.IsSuccessStatusCode)
            {
                var createdProductJson = await createResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"Product created successfully: {createdProductJson}\n");
            }
            else
            {
                Console.WriteLine($"Failed to create product. Status Code: {createResponse.StatusCode}");
                var errorContent = await createResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"Error: {errorContent}\n");
            }
            // Step Retrieve all products
            Console.WriteLine("Retrieving all products...");
            var getAllResponse = await httpClient.GetAsync($"{ResourceServerBaseUrl}/api/Products/GetAll");
            if (getAllResponse.IsSuccessStatusCode)
            {
                var productsJson = await getAllResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"Products: {productsJson}\n");
            }
            else
            {
                Console.WriteLine($"Failed to retrieve products. Status Code: {getAllResponse.StatusCode}");
                var errorContent = await getAllResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"Error: {errorContent}\n");
            }
            // Step Retrieve a specific product by ID
            Console.WriteLine("Retrieving product with ID 1...");
            var getByIdResponse = await httpClient.GetAsync($"{ResourceServerBaseUrl}/api/Products/GetById/1");
            if (getByIdResponse.IsSuccessStatusCode)
            {
                var productJson = await getByIdResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"Product Details: {productJson}\n");
            }
            else
            {
                Console.WriteLine($"Failed to retrieve product. Status Code: {getByIdResponse.StatusCode}");
                var errorContent = await getByIdResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"Error: {errorContent}\n");
            }
            // Step Update a product
            var updatedProduct = new
            {
                Name = "Smartphone Pro",
                Description = "An upgraded smartphone with enhanced features.",
                Price = 1199.99
            };
            Console.WriteLine("Updating product with ID 1...");
            var updateResponse = await httpClient.PutAsync(
                $"{ResourceServerBaseUrl}/api/Products/Update/1",
                new StringContent(JsonSerializer.Serialize(updatedProduct), Encoding.UTF8, "application/json"));
            if (updateResponse.IsSuccessStatusCode || updateResponse.StatusCode == System.Net.HttpStatusCode.NoContent)
            {
                Console.WriteLine("Product updated successfully.\n");
            }
            else
            {
                Console.WriteLine($"Failed to update product. Status Code: {updateResponse.StatusCode}");
                var errorContent = await updateResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"Error: {errorContent}\n");
            }
            // Step Delete a product
            Console.WriteLine("Deleting product with ID 1...");
            var deleteResponse = await httpClient.DeleteAsync($"{ResourceServerBaseUrl}/api/Products/Delete/1");
            if (deleteResponse.IsSuccessStatusCode || deleteResponse.StatusCode == System.Net.HttpStatusCode.NoContent)
            {
                Console.WriteLine("Product deleted successfully.\n");
            }
            else
            {
                Console.WriteLine($"Failed to delete product. Status Code: {deleteResponse.StatusCode}");
                var errorContent = await deleteResponse.Content.ReadAsStringAsync();
                Console.WriteLine($"Error: {errorContent}\n");
            }
        }
    }
}
