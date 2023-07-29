using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        string letters = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            string key_stream = "";
            string actual_key = "";
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
                // getting the index of letter of intersection in the vigenere tableau
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
            int first_idx = 0, second_idx = 0, idx = 0, i, j, k;
            string decrypted = "";

            // Getting the new key
            string key_stream = key;

            //decrypting the first part of the message
            for (i = 0; i < key_stream.Length; i++)
            {
                // to get the index of the letters in the alphabet
                for (j = 0; j < letters.Length; j++)
                {
                    if (cipherText[i] == letters[j])
                        first_idx = j;
                    if (key_stream[i] == letters[j])
                        second_idx = j;
                }
                decrypted += letters[((first_idx - second_idx) + 26) % 26];
            }

            // decrypting the rest of the message
            for (k = 0, i = key.Length; i < cipherText.Length; i++, k++)
            {
                // to get the index of the letters in the alphabet
                for (j = 0; j < letters.Length; j++)
                {
                    if (cipherText[i] == letters[j])
                        first_idx = j;
                    if (decrypted[k] == letters[j])
                        second_idx = j;
                }
                key_stream += decrypted[idx];
                decrypted += letters[((first_idx - second_idx) + 26) % 26];
            }
            return decrypted;
        }
        public string Encrypt(string plainText, string key)
        {
            string encrypted = "";
            int Text_idx = 0, key_idx = 0, i, j;

            // Getting the new key
            string key_stream = key;
            for (i = 0; i < (plainText.Length - key.Length); i++)
                key_stream += plainText[i];

            // encrypting the message
            for (i = 0; i < plainText.Length; i++)
            {
                // to get the index of the letters in the alphabet
                for (j = 0; j < letters.Length; j++)
                {
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
