using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {


            Dictionary<char, char> textsdict = new Dictionary<char, char>(); //key->plainText, value ->cipherText
            Dictionary<char, int> keydict = new Dictionary<char, int>();  //key
            char[] alph_letters = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

            cipherText = cipherText.ToLower();

            for (int i = 0; i < plainText.Length; i++)
            {
                if (!textsdict.ContainsKey(plainText[i]))
                {
                    textsdict[plainText[i]] = cipherText[i];
                }
            }

            StringBuilder word_text = new StringBuilder();
            for (int i = 0; i < alph_letters.Length; i++)
            {
                if (textsdict.ContainsKey(alph_letters[i]))
                {
                    word_text.Append(textsdict[alph_letters[i]]);
                    keydict[textsdict[alph_letters[i]]] = 1;
                }
                else
                {
                    word_text.Append(' ');
                }
            }

            for (int i = 0; i < word_text.Length - 1; i++)
            {
                if (word_text[i + 1] == ' ')
                {
                    char nxtChar = (char)(word_text[i] + 1);
                    for (int j = 0; j < 26; j++)
                    {
                        if (nxtChar == '{')
                        {
                            nxtChar = 'a';
                        }
                        if (keydict.ContainsKey(nxtChar))
                        {
                            nxtChar = (char)(nxtChar + 1);
                        }
                        else
                        {
                            keydict[nxtChar] = 1;
                            word_text[i + 1] = nxtChar;
                            break;
                        }
                    }
                }
            }
            string key = word_text.ToString();
            return key;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string plain_text = string.Empty;
            char[] alph_letters = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        plain_text += alph_letters[j];
                    }
                }
            }
            return plain_text;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string cipher_text = string.Empty;
            char[] alph_letters = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < alph_letters.Length; j++)
                {
                    if (plainText[i] == alph_letters[j])
                    {
                        cipher_text += key[j];
                    }
                }
            }
            return cipher_text;
            // throw new NotImplementedException();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            char[] alph_letters = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            char[] frequencyOFletters = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };

            Dictionary<char, char> key = new Dictionary<char, char>();
            Dictionary<char, int> chars_inCipher = new Dictionary<char, int>();  //each character with its frequency in the cipher text

            StringBuilder newkey = new StringBuilder();
            StringBuilder finalKey = new StringBuilder();

            cipher = cipher.ToLower();

            for (int i = 0; i < cipher.Length; i++)
            {
                if (chars_inCipher.ContainsKey(cipher[i]))
                {
                    chars_inCipher[cipher[i]]++;
                }
                else
                {
                    chars_inCipher[cipher[i]] = 1;
                }
            }
            var alphabetDict = from character in chars_inCipher orderby character.Value descending select character;  //sorting letters in descending values

            foreach (var keyy in alphabetDict)
            {
                newkey.Append(keyy.Key);
            }
            for (int i = 0; i < 26; i++)
            {
                key[frequencyOFletters[i]] = newkey[i];
            }
            for (int i = 0; i < 26; i++)
            {
                finalKey.Append(key[alph_letters[i]]);
            }
            string plain_text = Decrypt(cipher, finalKey.ToString());
            return plain_text;
            //throw new NotImplementedException();
        }
    }
}