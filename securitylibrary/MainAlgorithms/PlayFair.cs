using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {

            key = key.ToUpper();
            string unique_characters = string.Empty;
            int count = 0; //counter for matrix
            string alph_char = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            StringBuilder alph_string = new StringBuilder(alph_char);
            var set_of_chars = new HashSet<char>(key);
            string string_with_nospaces = string.Empty;

            foreach (char character in set_of_chars)
            {
                unique_characters += character;
            }

            //Remove charachters of key from alpha
            for (int i = 0; i < unique_characters.Length; i++)
            {
                for (int j = 0; j < 24; j++)
                {
                    if (unique_characters[i] == alph_char[j])
                    {
                        alph_string[j] = ' ';
                    }
                }
            }
            for (int i = 0; i < alph_string.Length; i++)
            {
                if (alph_string[i] != ' ')
                {
                    string_with_nospaces += alph_string[i];
                }
            }

            string chars_of_matrix = unique_characters + string_with_nospaces;
            char[,] matrix = new char[5, 5];

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = chars_of_matrix[count];
                    count++;
                }
            }
            // divide each two chars
            cipherText = cipherText.ToUpper();
            var double_char = new List<string>();

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                double_char.Add(cipherText.Substring(i, 2));
            }

            StringBuilder plainText = new StringBuilder();
            int corner1 = -1, corner2 = -1, corner3 = -1, corner4 = -1;
            for (int n = 0; n < double_char.Count(); n++)
            {
                string two_chars = double_char[n];
                ///STORE I AND J ////
                for (int k = 0; k < 2; k++)
                {
                    for (int i = 0; i < 5; i++)
                    {
                        for (int j = 0; j < 5; j++)
                        {
                            if (k == 0)
                            {
                                if (matrix[i, j] == two_chars[k])
                                {
                                    corner1 = i;
                                    corner2 = j;
                                }
                            }
                            else
                            {
                                if (matrix[i, j] == two_chars[k])
                                {
                                    corner3 = i;
                                    corner4 = j;
                                }

                            }
                        }
                    }
                }
                //swapping

                if (corner1 == corner3)
                {
                    if (corner2 == 0)
                    {
                        corner2 = 5;
                    }
                    if (corner4 == 0)
                    {
                        corner4 = 5;
                    }
                    corner2 = ((corner2 - 1) % (5));
                    corner4 = ((corner4 - 1) % (5));
                    plainText.Append(matrix[corner1, corner2]);
                    plainText.Append(matrix[corner3, corner4]);
                }
                else if (corner4 == corner2)
                {
                    if (corner1 == 0)
                    {
                        corner1 = 5;
                    }
                    if (corner3 == 0)
                    {
                        corner3 = 5;
                    }
                    corner1 = ((corner1 - 1) % (5));
                    corner3 = ((corner3 - 1) % (5));
                    plainText.Append(matrix[corner1, corner2]);
                    plainText.Append(matrix[corner3, corner4]);
                }
                else
                {
                    plainText.Append(matrix[corner1, corner4]);
                    plainText.Append(matrix[corner3, corner2]);
                }
                corner1 = 0;
                corner2 = 0;
                corner3 = 0;
                corner4 = 0;
            }
            // remove last x from string //
            if (plainText[plainText.Length - 1] == 'X')
            {
                plainText.Remove(plainText.Length - 1, 1);
            }
            //remove extra x
            string plainTextt = plainText.ToString();
            StringBuilder x_removed = new StringBuilder(plainTextt);
            for (int i = 1; i < x_removed.Length; i = i + 2)
            {
                if (x_removed[i] == 'X' && x_removed[i + 1] == x_removed[i - 1])
                {
                    x_removed.Remove(i, 1);
                    i++;
                }
            }
            string plain_text = x_removed.ToString();
            return plain_text;
        }


        public string Encrypt(string plainText, string key)
        {

            key = key.ToUpper();
            string unique_characters = string.Empty;
            string cipher_text = string.Empty;
            var set_of_chars = new HashSet<char>(key);
            int count = 0; //counter for matrix
            string alph_letters = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            StringBuilder alph_string = new StringBuilder(alph_letters);
            string string_with_nospaces = string.Empty;
            char[,] matrix = new char[5, 5];
            plainText = plainText.ToUpper();
            int corner1 = -1, corner2 = -1, corner3 = -1, corner4 = -1;


            //getting unique characters
            foreach (char character in set_of_chars)
            {
                unique_characters += character;
            }

            //remove the key characters from the alphabetics
            for (int i = 0; i < unique_characters.Length; i++)
            {
                for (int j = 0; j < 24; j++)
                {
                    if (unique_characters[i] == alph_letters[j])
                    {
                        alph_string[j] = ' ';
                    }
                }
            }

            for (int i = 0; i < alph_string.Length; i++)
            {
                if (alph_string[i] != ' ')
                {
                    string_with_nospaces += alph_string[i];
                }
            }
            //filling the key_matrix with key and the rest of the letters
            string chars_of_matrix = unique_characters + string_with_nospaces;

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {

                    matrix[i, j] = chars_of_matrix[count];
                    count++;
                }
            }
            //add x 
            int length = plainText.Length;
            for (int i = 0; i < length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "X");
                    length++;
                }
            }
            //insert x at the last of string
            string final_text = plainText;
            if (final_text.Length % 2 != 0)
            {
                final_text += 'X';
            }

            // splitting into two characters together
            var double_char = new List<string>();
            for (int i = 0; i < final_text.Length; i += 2)
            {
                double_char.Add(final_text.Substring(i, 2));
            }

            //encryption 
            for (int n = 0; n < double_char.Count(); n++)
            {
                string two_char = double_char[n];  //eah two characters

                for (int k = 0; k < 2; k++)
                {
                    for (int i = 0; i < 5; i++)
                    {
                        for (int j = 0; j < 5; j++)
                        {
                            if (k == 0)
                            {
                                if (matrix[i, j] == two_char[k])
                                {
                                    corner1 = i;
                                    corner2 = j;
                                }
                            }
                            else
                            {
                                if (matrix[i, j] == two_char[k])
                                {
                                    corner3 = i;
                                    corner4 = j;
                                }
                            }
                        }
                    }
                }
                //replacing
                if (corner1 == corner3)
                {
                    corner2 = (corner2 + 1) % 5;
                    corner4 = (corner4 + 1) % 5;
                    cipher_text += matrix[corner1, corner2];
                    cipher_text += matrix[corner3, corner4];
                }
                else if (corner4 == corner2)
                {
                    corner1 = (corner1 + 1) % 5;
                    corner3 = (corner3 + 1) % 5;
                    cipher_text += matrix[corner1, corner2];
                    cipher_text += matrix[corner3, corner4];
                }
                else
                {
                    cipher_text += matrix[corner1, corner4];
                    cipher_text += matrix[corner3, corner2];
                }
                corner1 = 0;
                corner2 = 0;
                corner3 = 0;
                corner4 = 0;
            }
            return cipher_text;
        }
    }
}