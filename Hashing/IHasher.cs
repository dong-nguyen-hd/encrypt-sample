namespace EncryptSample.Hashing
{
    public interface IHasher
    {
        string CreateHash(string plainText, BaseCryptographyItem.HashAlgorithm algorithm);
        string CreateHash(string plainText, string salt, BaseCryptographyItem.HashAlgorithm algorithm);
        bool MatchesHash(string plainText, string hash);
    }
}
