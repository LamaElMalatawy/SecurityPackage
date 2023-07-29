using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        string letters = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            string key_stream = "", actual_key = "";
            int plain_idx = 0, cipher_idx = 0, i, j, k;

            for (i = 0; i < cipherText.Length; i++)
            {
                // getting the index of the letter in the alphabet
                for (j = 0; j < letters.Length; j++)
                {
                    if (cipherText[i] == letters[j])
                        cipher_idx = j;
                    if (plainText[i] == letters[j])
                        plain_idx = j;
                }
                // getting the letter of intersection in the vigenere tableau
                key_stream += letters[((cipher_idx - plain_idx) + 26) % 26];
            }
            actual_key += key_stream[0];
            for (k = 1; k < key_stream.Length; k++)
            {
                actual_key += key_stream[k];
                if (plainText.Equals(Decrypt(cipherText, actual_key)))
                    break;
                else
                    continue;
            }
            return actual_key;
        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string decrypted = "";
            int Text_idx = 0, key_idx = 0, i, j;

            // Getting the new key
            string key_stream = key;
            for (i = 0, j = 0; i < (cipherText.Length - key.Length); i++, j++)
            {
                //if the key letters are finished --> repeat
                if (j == key.Length)
                    j = 0;
                key_stream += key[j];
            }

            // decrypting the message
            for (i = 0; i < cipherText.Length; i++)
            {
                // to get the index of the letters in the alphabet
                for (j = 0; j < letters.Length; j++)
                {
                    if (cipherText[i] == letters[j])
                        Text_idx = j;
                    if (key_stream[i] == letters[j])
                        key_idx = j;
                }
                // getting the index of letter of intersection in the vigenere tableau
                decrypted += letters[((Text_idx - key_idx) + 26) % 26];
            }
            return decrypted;
        }
        public string Encrypt(string plainText, string key)
        {
            string encrypted = "";
            int Text_idx = 0, key_idx = 0, i, j;

            // Getting the new key
            string key_stream = key;
            for (i = 0, j = 0; i < (plainText.Length - key.Length); i++, j++)
            {
                if (j == key.Length) //if the key letters are finished --> repeat
                    j = 0;
                key_stream += key[j];
            }

            // encrypting the message
            for (i = 0; i < plainText.Length; i++)
            {
                for (j = 0; j < letters.Length; j++)
                {
                    // to get the index of the intersecting letters in the alphabet
                    if (plainText[i] == letters[j])
                        Text_idx = j;
                    if (key_stream[i] == letters[j])
                        key_idx = j;
                }
                // getting the letter of intersection in the vigenere tableau
                encrypted += letters[(Text_idx + key_idx) % 26];
            }
            return encrypted;
        }
    }
}