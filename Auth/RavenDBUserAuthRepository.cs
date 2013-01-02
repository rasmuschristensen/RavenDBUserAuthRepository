using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using Raven.Client;
using ServiceStack.Common.Extensions;
using ServiceStack.ServiceInterface.Auth;

namespace Auth
{
    public class RavenDBUserAuthRepository
    {
        //http://stackoverflow.com/questions/3588623/c-sharp-regex-for-a-username-with-a-few-restrictions
        public Regex ValidUserNameRegEx = new Regex(@"^(?=.{3,15}$)([A-Za-z0-9][._-]?)*$", RegexOptions.Compiled);
        private readonly IDocumentStore _documentStore;

        public RavenDBUserAuthRepository(IDocumentStore documentStore)
        {
            _documentStore = documentStore;
        }

        private void ValidateNewUser(UserAuth newUser, string password)
        {
            newUser.ThrowIfNull("newUser");
            password.ThrowIfNullOrEmpty("password");

            if (newUser.UserName.IsNullOrEmpty() && newUser.Email.IsNullOrEmpty())
                throw new ArgumentNullException("UserName or Email is required");

            if (!newUser.UserName.IsNullOrEmpty())
            {
                if (!ValidUserNameRegEx.IsMatch(newUser.UserName))
                    throw new ArgumentException("UserName contains invalid characters", "UserName");
            }
        }

        /// <summary>
        /// Check if there is already an existing user with the same username or email
        /// </summary>
        /// <param name="user"></param>
        private void AssertNoExistingUser(UserAuth user)
        {
            UserAuth existingUser = null;

            if (string.IsNullOrWhiteSpace(user.UserName))
            {
                existingUser = GetUserAuthByUserName(user.UserName);
            }

            if (existingUser == null && string.IsNullOrWhiteSpace(user.Email))
            {
                existingUser = GetUserAuthByUserName(user.Email);
            }

            if (existingUser != null)
            {
                throw new ArgumentException("User already exists");
            }
        }

        public UserAuth CreateUserAuth(UserAuth newUser, string password)
        {
            ValidateNewUser(newUser, password);

            AssertNoExistingUser(newUser);

            using (var session = _documentStore.OpenSession())
            {
                var saltedHash = new SaltedHash();
                string salt;
                string hash;
                saltedHash.GetHashAndSaltString(password, out hash, out salt);
                var digestHelper = new DigestAuthFunctions();
                newUser.DigestHA1Hash = digestHelper.CreateHa1(newUser.UserName, DigestAuthProvider.Realm, password);
                newUser.PasswordHash = hash;
                newUser.Salt = salt;
                newUser.CreatedDate = DateTime.UtcNow;
                newUser.ModifiedDate = newUser.CreatedDate;

                session.Store(newUser);
                session.SaveChanges();

                return newUser;
            }
        }


        public UserAuth UpdateUserAuth(UserAuth existingUser, UserAuth newUser, string password)
        {
            throw new System.NotImplementedException();
        }

        public UserAuth GetUserAuthByUserName(string userNameOrEmail)
        {
            using (var session = _documentStore.OpenSession())
            {
                var isEmail = userNameOrEmail.Contains("@");
                var userAuth = isEmail
                    ? session.Query<UserAuth>().Where(x => x.Email == userNameOrEmail).FirstNonDefault()
                    : session.Query<UserAuth>().Where(x => x.UserName == userNameOrEmail).FirstNonDefault();

                return userAuth;
            }
        }

        public bool TryAuthenticate(string userName, string password, out UserAuth userAuth)
        {
            userAuth = GetUserAuthByUserName(userName);
            if (userAuth == null) return false;

            var saltedHash = new SaltedHash();
            if (saltedHash.VerifyHashString(password, userAuth.PasswordHash, userAuth.Salt))
            {
                return true;
            }

            userAuth = null;
            return false;
        }

        public bool TryAuthenticate(Dictionary<string, string> digestHeaders, string PrivateKey, int NonceTimeOut, string sequence,
                                    out UserAuth userAuth)
        {
            userAuth = GetUserAuthByUserName(digestHeaders["username"]);
            if (userAuth == null) return false;

            var digestHelper = new DigestAuthFunctions();
            if (digestHelper.ValidateResponse(digestHeaders, PrivateKey, NonceTimeOut, userAuth.DigestHA1Hash, sequence))
            {
                return true;
            }
            userAuth = null;
            return false;
        }

        public void LoadUserAuth(IAuthSession session, IOAuthTokens tokens)
        {
            session.ThrowIfNull("session");

            var userAuth = GetUserAuth(session, tokens);
            LoadUserAuth(session, userAuth);
        }

        public UserAuth GetUserAuth(string userAuthId)
        {
            var id = int.Parse(userAuthId);

            using (var session = _documentStore.OpenSession())
            {
                return session.Load<UserAuth>().FirstOrDefault(x => x.Id == id);
            }

            return null;
        }

        private void LoadUserAuth(IAuthSession session, UserAuth userAuth)
        {
            if (userAuth == null) return;

            var idSesije = session.Id;  //first record session Id (original session Id)
            session.PopulateWith(userAuth); //here, original sessionId is overwritten with facebook user Id
            session.Id = idSesije;  //we return Id of original session here

            session.UserAuthId = userAuth.Id.ToString(CultureInfo.InvariantCulture);
            session.ProviderOAuthAccess = GetUserOAuthProviders(session.UserAuthId)
                .ConvertAll(x => (IOAuthTokens)x);

        }

        public void SaveUserAuth(IAuthSession authSession)
        {
            using (var session = _documentStore.OpenSession())
            {
                var id = int.Parse(authSession.UserAuthId);
                var userAuth = !authSession.UserAuthId.IsNullOrEmpty()
                    ? session.Load<UserAuth>().FirstOrDefault(x => x.Id == id)
                    : authSession.TranslateTo<UserAuth>();

                if (userAuth.Id == default(int) && !authSession.UserAuthId.IsNullOrEmpty())
                    userAuth.Id = int.Parse(authSession.UserAuthId);

                userAuth.ModifiedDate = DateTime.UtcNow;
                if (userAuth.CreatedDate == default(DateTime))
                    userAuth.CreatedDate = userAuth.ModifiedDate;

                session.Store(userAuth);
                session.SaveChanges();
            }
        }

        public void SaveUserAuth(UserAuth userAuth)
        {
            userAuth.ModifiedDate = DateTime.UtcNow;
            if (userAuth.CreatedDate == default(DateTime))
                userAuth.CreatedDate = userAuth.ModifiedDate;

            using (var session = _documentStore.OpenSession())
            {
                session.Store(userAuth);
                session.SaveChanges();
            }
        }

        public List<UserOAuthProvider> GetUserOAuthProviders(string userAuthId)
        {
            var id = int.Parse(userAuthId);

            using (var session = _documentStore.OpenSession())
            {
                return session.Load<UserOAuthProvider>().Where(x => x.UserAuthId == id).ToList();
            }
        }

        public UserAuth GetUserAuth(IAuthSession authSession, IOAuthTokens tokens)
        {
            if (!authSession.UserAuthId.IsNullOrEmpty())
            {
                var userAuth = GetUserAuth(authSession.UserAuthId);
                if (userAuth != null) return userAuth;
            }
            if (!authSession.UserAuthName.IsNullOrEmpty())
            {
                var userAuth = GetUserAuthByUserName(authSession.UserAuthName);
                if (userAuth != null) return userAuth;
            }

            if (tokens == null || tokens.Provider.IsNullOrEmpty() || tokens.UserId.IsNullOrEmpty())
                return null;


            using (var session = _documentStore.OpenSession())
            {
                var oAuthProvider = session.Load<UserOAuthProvider>()
                       .FirstOrDefault(x => x.Provider == tokens.Provider && x.UserId == tokens.UserId);

                if (oAuthProvider != null)
                {
                    var userAuth = session.Load<UserAuth>().FirstOrDefault(x => x.Id == oAuthProvider.UserAuthId);
                    return userAuth;
                }
                return null;
            }
        }

        public string CreateOrMergeAuthSession(IAuthSession authSession, IOAuthTokens tokens)
        {
            var userAuth = GetUserAuth(authSession, tokens) ?? new UserAuth();

            using (var session = _documentStore.OpenSession())
            {
                var oAuthProvider = session.Load<UserOAuthProvider>().FirstOrDefault(q =>
                       q.Provider == tokens.Provider && q.UserId == tokens.UserId);

                if (oAuthProvider == null)
                {
                    oAuthProvider = new UserOAuthProvider

                    {
                        Provider = tokens.Provider,
                        UserId = tokens.UserId,
                    };
                }

                oAuthProvider.PopulateMissing(tokens);
                userAuth.PopulateMissing(oAuthProvider);

                userAuth.ModifiedDate = DateTime.UtcNow;
                if (userAuth.CreatedDate == default(DateTime))
                    userAuth.CreatedDate = userAuth.ModifiedDate;

                session.Store(userAuth);
                session.SaveChanges();

                //oAuthProvider.UserAuthId = userAuth.Id != default(int)
                //    ? userAuth.Id
                //    : (int)db.GetLastInsertId();

                if (oAuthProvider.CreatedDate == default(DateTime))
                    oAuthProvider.CreatedDate = userAuth.ModifiedDate;
                oAuthProvider.ModifiedDate = userAuth.ModifiedDate;

                session.Store(oAuthProvider);
                session.SaveChanges();

                return oAuthProvider.UserAuthId.ToString(CultureInfo.InvariantCulture);
            }
        } 
    }
}