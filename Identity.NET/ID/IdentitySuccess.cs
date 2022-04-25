namespace Identity.NET.Id
{
    internal struct IdentitySuccess
    {
        public IdentitySuccess(bool success, string identity)
        {
            Success = success;
            Identity = identity;
        }

        public bool Success { get; set; }
        public string Identity { get; set; }
    }
}
