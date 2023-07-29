using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int key)
        {
            string cipher_text = string.Empty;
            for (int i = 0; i < plainText.Length; i++)
            {
                char ch = plainText[i];
                char letter = char.IsUpper(ch) ? 'A' : 'a';
                cipher_text += (char)((((ch + key) - letter) % 26) + letter);
            }
            //throw new NotImplementedException();
            return cipher_text;
        }

        public string Decrypt(string cipherText, int key)
        {
            return Encrypt(cipherText, 26 - key);
            //throw new NotImplementedException();
        }

        public int Analyse(string plainText, string cipherText)
        {
            char letter1 = (cipherText[0]);
            char letter2 = char.ToUpper(plainText[0]);

            int key = (letter1 - letter2) % 26;
            if (key < 0)
                key = key + 26;

            return key;
        }
    }
}