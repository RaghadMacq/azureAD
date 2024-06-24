using System.DirectoryServices.AccountManagement;
using System;
using System.DirectoryServices.Protocols;
using System.Net;
namespace azureAD
{

    public class LdapService
    {
        private readonly string _domain;
        private readonly int _port;
        private readonly string _username;
        private readonly string _password;

        public LdapService(string domain, int port, string username, string password)
        {
            _domain = domain;
            _port = port;
            _username = username;
            _password = password;
        }

        public bool ValidateUser(string username, string password)
        {
            try
            {
                var ldapIdentifier = new LdapDirectoryIdentifier(_domain, _port);

                using (var ldapConnection = new LdapConnection(ldapIdentifier))
                {
                    var networkCredential = new NetworkCredential(_username, _password);
                    ldapConnection.Credential = networkCredential;
                    ldapConnection.AuthType = AuthType.Basic;

                    ldapConnection.Bind();

                    // If bind is successful, validate user credentials
                    var userCredential = new NetworkCredential(username, password);
                    ldapConnection.Bind(userCredential);

                    return true;
                }
            }
            catch (LdapException ex)
            {
                // Log the exception
                Console.WriteLine($"LDAP Error: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"Error: {ex.Message}");
                return false;
            }
        }
    }

}
