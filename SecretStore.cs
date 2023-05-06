namespace EncryptSample
{
    public interface ISecretStore
    {
        string GetKey(string keyName, int keyIndex);
        string GetSalt(string saltName);
    }

    public class SecretStore : ISecretStore
    {
        //FOR TESTING/DEMONSTRATION ONLY!!!
        //KEYS SHOULD BE STORED SECURELY, NOT HARD-CODED IN THE APP!!!
        public string GetKey(string keyName, int keyIndex)
        {
            //Use Key Index to rotate keys if needed

            if (keyIndex == 1)
            {
                return "C4618965275F268175D42F6D9143A935";
            }
            else if (keyIndex == 2)
            {
                return "B2A1F652A46B89CBBCD1CCD4DF4FC4BB";
            }
            else
                throw new NotImplementedException($"Cannot find keys for key index: {keyIndex}");
        }

        //Hard-coded salts are a terrible idea! These are here for demonstration purposes only!!!
        public string GetSalt(string saltName)
        {
            return "1969583C833B246BE394176FDA7A9E21B2A1F652A46B89CBBCD1CCD4DF4FC4BB";
        }
    }
}
