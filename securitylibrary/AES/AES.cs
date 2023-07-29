using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Collections;
namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>

    public class AES : CryptographicTechnique
    {
        //declarations
       
        private int[,] matrix = new int[4, 4];

        private string[,] afterSubBytes = new string[4, 4];

        string[,] afterColumnMix = new string[4, 4];
        
        string[,] keySchedule = new string[4, 44];

        private string[,] S_Box = new string[,] 
        {
            {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
            {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
            {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
            {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
            {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
            {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
            {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
            {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
            {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
            {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
            {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
            {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
            {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
            {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
            {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
            {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}
        };

        string[] Rcon = new string[] 
        { 
            "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" 
        };


        //helper functions
        public void getKeySchedule(string key)
        {
            int idx = 2;

            for(int i=0;i<16;i++)
            {
                if(i>=0 && i<4)
                    keySchedule[(idx / 2) - 1, 0] = key.Substring(idx, 2);

                else if(i>=4 && i<8)
                    keySchedule[((idx / 2) - 1) - 4, 1] = key.Substring(idx, 2);

                else if(i>=8 && i<12)
                    keySchedule[((idx / 2) - 1) - 8, 2] = key.Substring(idx, 2);

                else
                    keySchedule[((idx / 2) - 1) - 12, 3] = key.Substring(idx, 2);

                idx += 2;


            }
           

            for (int j = 4; j < 44; j = j + 4)
            {
                for (int i = 0; i < 4; i++)
                {
                    keySchedule[i, j]= keySchedule[(i + 1) % 4, j - 1];
                }

                subBytesKeySchedule(j);

                string hexa1, hexa2;
                int x, y, z;
                
                for (int i = 0; i < 4; i++)
                {
                    hexa1 = keySchedule[i, j - 4].Substring(0, keySchedule[i, j - 4].Count());
                    hexa2 = keySchedule[i, j].Substring(0, keySchedule[i, j].Count());

                    x = Convert.ToInt32(hexa1, 16);
                    y = Convert.ToInt32(hexa2, 16);

                    if(i==0)
                    {
                        z = Convert.ToInt32(Rcon[(j / 4) - 1], 16);
                        keySchedule[i, j] = (x ^ y ^ z).ToString("X");
                    }
                       
                    else
                        keySchedule[i, j] = (x ^ y).ToString("X");
                }

                for (int i = j + 1; i < j + 4; i++)
                {

                    for (int k = 0; k < 4; k++)
                    {
                        hexa1 = keySchedule[k, i - 4].Substring(0, keySchedule[k, i - 4].Count());
                        hexa2 = keySchedule[k, i - 1].Substring(0, keySchedule[k, i - 1].Count());

                        x = Convert.ToInt32(hexa1, 16);
                        y = Convert.ToInt32(hexa2, 16);

                        keySchedule[k, i] = (x ^ y).ToString("X");

                    }
                }
            }
        }

        public void subBytesKeySchedule(int index)
        {
            string hexa1, hexa2;
            for (int i = 0; i < 4; i++)
            {
                if (keySchedule[i, index].Count() == 1)
                    keySchedule[i, index] = S_Box[0, Convert.ToInt32(keySchedule[i, index], 16)];

                else
                {
                    hexa1 = keySchedule[i, index].Substring(0, 1);
                    hexa2 = keySchedule[i, index].Substring(1, 1);

                    keySchedule[i, index] = S_Box[Convert.ToInt32(hexa1, 16), Convert.ToInt32(hexa2, 16)];
                }
            }
        }

        public void firstRound(string plainText, string key)
        {
            string keySubstr, textSubstr;
            int xor, idx = 2;

            for(int i = 0; i < 16; i++)
            {
                textSubstr = plainText.Substring(idx, 2);
                keySubstr = key.Substring(idx, 2);

                xor = Convert.ToInt32(textSubstr, 16) ^ Convert.ToInt32(keySubstr, 16);
               
                if (i >= 0 && i < 4)
                    matrix[(idx / 2) - 1, 0] = xor;
                else if (i >= 4 && i < 8)
                    matrix[((idx / 2) - 1) - 4, 1] = xor;
                else if (i >= 8 && i < 12)
                    matrix[((idx / 2) - 1) - 8, 2] = xor;
                else
                    matrix[((idx / 2) - 1) - 12, 3] = xor;

                idx += 2;
            }

      
        }

        public string getFromS_box(int number)
        {
            string hex = number.ToString("X");
            int i, j;

            if (hex.Count() == 1)
            {
                j = Convert.ToInt32(hex, 16);
                return S_Box[0,j];

            }

            i = Convert.ToInt32(hex.Substring(0, 1), 16);
            j = Convert.ToInt32(hex.Substring(1, 1), 16);
            return S_Box[i,j];
        }

        public void subBytesTransformation()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    afterSubBytes[i, j] = getFromS_box(matrix[i, j]);
                }
            }
        }

        public void reverseSubBytesTransformation()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string str = inverse_SubByte_Helper(convertIntToHexa(matrix[i, j]));
                    matrix[i, j] = Convert.ToInt32(str, 16);
                }
            }
        }

        public string inverse_SubByte_Helper(string cell)
        {

            for (int row = 0; row < 16; row++)
            {
                for (int col = 0; col < 16; col++)
                {
                    if (S_Box[row, col].ToUpper() == cell)
                    {
                        return row.ToString("X") + col.ToString("X");
                    }
                }
            }
            return "";
        }

        public string shift_specificRow(int row, string col0, string col1, string col2, string col3)
        {
            if (row == 1)
                return col1 + col2 + col3 + col0;
            if (row == 2)
                return col2 + col3 + col0 + col1;
            if (row == 3)
                return col3 + col0 + col1 + col2;
            return "";
        }

        public void shiftRowsTransformation()
        {
            string shiftedRow;
            for (int i = 1; i < 4; i++)
            {
                shiftedRow = shift_specificRow(i, afterSubBytes[i, 0], afterSubBytes[i, 1], afterSubBytes[i, 2], afterSubBytes[i, 3]);
                for (int j = 0; j < 4; j++)
                {
                    afterSubBytes[i, j] = shiftedRow.Substring(j * 2, 2);
                }
            }
        }

        public string convertIntToHexa(int number)
        {
            string str = number.ToString("X");
            if (str.Length == 1)
                return "0" + str;

            return str;
        }

        public void reverseShiftRowsTransformation()
        {
            string unshiftedRow;
            for (int i = 1; i < 4; i++)
            {
                unshiftedRow = shift_specificRow(
                        4 - i
                       , convertIntToHexa(matrix[i, 0])
                       , convertIntToHexa(matrix[i, 1])
                       , convertIntToHexa(matrix[i, 2])
                       , convertIntToHexa(matrix[i, 3])
                   );

                for (int j = 0; j < 4; j++)
                {
                    matrix[i, j] = Convert.ToInt32(unshiftedRow.Substring(j * 2, 2), 16);
                }
            }
        }

        public int getZeroTwo(string num)
        {
            int hex = Convert.ToInt32(num, 16);
            string bi = Convert.ToString(hex, 2);
            string str;

            //most left is one
            if (bi.Count() == 8)
            {
                // remove the leftmost bit and add 0 on the right 
                str = bi.Substring(1, bi.Count() - 1) + "0";
                return (Convert.ToInt32(str, 2) ^ Convert.ToInt32("1B", 16));
            }
            // else add 0 on the right
            str = bi.Substring(0, bi.Count()) + "0";
            return Convert.ToInt32(str, 2);
        }

        public int getZeroThree(string num)
        {
            return (getZeroTwo(num) ^ Convert.ToInt32(num, 16));

        }

        public string convert()
        {
            string text = "0x";
            string str;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    str = matrix[j, i].ToString("X");
                    if (str.Length == 1)
                        str = "0" + str;
                    text += str;
                }
            }
            return text;
        }

        public void mixColumnsTransformation()
        {
            string[,] mat = new string[,] { 
                { "02", "03", "01", "01" },
                { "01", "02", "03", "01" },
                { "01", "01", "02", "03" },
                { "03", "01", "01", "02" } 
            };

            int xor, res;
            for (int col = 0; col < 4; col++)
            {
                xor = 0;
                for (int j = 0; j < 4; j++)
                {
                    if (mat[0, j] == "01")
                        xor = xor ^ Convert.ToInt32(afterSubBytes[j, col], 16);

                    else
                    {
                        if (mat[0, j] == "02")
                            res = getZeroTwo(afterSubBytes[j, col]);

                        else
                            res = getZeroThree(afterSubBytes[j, col]);

                        xor = xor ^ res;
                    }
                   
                }

                afterColumnMix[0, col] = xor.ToString("X");

                xor = 0;
                for (int j = 0; j < 4; j++)
                {
                    if (mat[1, j] == "01")
                        xor = xor ^ Convert.ToInt32(afterSubBytes[j, col], 16);

                    else
                    {
                        if (mat[1, j] == "02")
                            res = getZeroTwo(afterSubBytes[j, col]);

                        else
                            res = getZeroThree(afterSubBytes[j, col]);

                        xor = xor ^ res;
                    }
                }

                afterColumnMix[1, col] = xor.ToString("X");

                xor = 0;
                for (int j = 0; j < 4; j++)
                {
                    if (mat[2, j] == "01")
                        xor = xor ^ Convert.ToInt32(afterSubBytes[j, col], 16);

                    else
                    {
                        if (mat[2, j] == "02")
                            res = getZeroTwo(afterSubBytes[j, col]);

                        else
                            res = getZeroThree(afterSubBytes[j, col]);

                        xor = xor ^ res;
                    }
                }

                afterColumnMix[2, col] = xor.ToString("X");

                xor = 0;
                for (int j = 0; j < 4; j++)
                {
                    if (mat[3, j] == "01")
                        xor = xor ^ Convert.ToInt32(afterSubBytes[j, col], 16);

                    else
                    {
                        if (mat[3, j] == "02")
                            res = getZeroTwo(afterSubBytes[j, col]);

                        else
                            res = getZeroThree(afterSubBytes[j, col]);

                        xor = xor ^ res;
                    }

                }
                afterColumnMix[3, col] = xor.ToString("X");
            }
        }

        public string ReverseString(string str)
        {
            char[] ans = str.ToCharArray();
            Array.Reverse(ans);
            return new string(ans);
        }

        public string zeroRemoval(string num)
        {
            for (int i = 0; i < num.Count(); i++)
            {
                if (num[i] != '0')
                    return num.Substring(i);

            }
            return "";
        }

        public string getRemainder(string num)
        {
            string baseNumber = "100011011";
            string ans;

            if (num.Count() < baseNumber.Count())
                return num;

            char[] res = new char[num.Count()];
            int diffrence = num.Count() - baseNumber.Count();

            for (int i = 0; i < baseNumber.Count(); i++)
            {
                if (baseNumber[i] == num[i])
                    res[i] = '0';
                else
                    res[i] = '1';
            }

            diffrence--;
            for (int i = baseNumber.Count(); i < num.Count(); i++)
            {
                res[i] = num[i];
            }

            ans = new string(res);
            ans = zeroRemoval(ans);
            if (ans.Count() < 9)
                return getRemainder(ans);

            int counter = 1;
            while (diffrence >= 0)
            {
                for (int i = 0; i < baseNumber.Count(); i++)
                {
                    if (baseNumber[i] == res[i + counter])
                        res[i + counter] = '0';
                    else
                        res[i + counter] = '1';
                }

                if (diffrence > 0)
                    res[baseNumber.Count() + counter] = num[baseNumber.Count() + counter];

                diffrence--;
                counter++;

                ans = new string(res);
                ans = zeroRemoval(ans);

                if (ans.Count() < 9)
                    return getRemainder(ans);
            }

            ans = new string(res);
            ans = zeroRemoval(ans);

            if (ans.Count() > 9)
                return getRemainder(ans);

            return ans;
        }

        public void reverseMixColumns()
        {
            string[,] mat = new string[,] { 
                { "0e", "0b", "0d", "09" },
                { "09", "0e", "0b", "0d" },
                { "0d", "09", "0e", "0b" },
                { "0b", "0d", "09", "0e" } 
            };

            string[] text = new string[64];
            int textIdx = 0;

            for (int i = 0; i < 4; i++)
            {
                for (int cell = 0; cell < 4; cell++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        string matbin = ReverseString(Convert.ToString(Convert.ToInt64(mat[cell, j], 16), 2));
                        string normbin = ReverseString(Convert.ToString(matrix[j, i], 2));
                        string strr = convertIntToHexa(matrix[j, i]);
                        int[] poly = new int[matbin.Count() + normbin.Count()];

                        for (int x = matbin.Count() - 1; x >= 0; x--)
                        {
                            if (matbin[x] == '0')
                                continue;

                            for (int y = normbin.Count() - 1; y >= 0; y--)
                            {
                                if (normbin[y] == '0')
                                    continue;
                                poly[x + y]++;
                            }
                        }

                        for (int x = 0; x < poly.Count(); x++)
                        {
                            if (poly[x] == 0)
                                continue;
                            if (poly[x] % 2 == 0)
                                poly[x] = 0;
                            else
                                poly[x] = 1;

                        }
                        poly[0] = poly[0];

                        text[textIdx] = string.Join("", poly);
                        text[textIdx] = zeroRemoval(ReverseString(text[textIdx]));
                        textIdx++;
                    }
                }
            }

            textIdx = textIdx + 0;
            for (int i = 0; i < textIdx; i++)
            {
                text[i] = zeroRemoval(getRemainder(text[i]));
            }

            int row = 0, col = 0;
            for (int i = 0; i < textIdx; i = i + 4)
            {
                string sd = ReverseString(xor_numbers(ReverseString(xor_numbers(text[i], text[i + 1])), ReverseString(xor_numbers(text[i + 3], text[i + 2]))));

                int num = Convert.ToInt32(sd, 2);
                matrix[row % 4, col] = num;

                row++;
                if ((i + 4) % 16 == 0)
                    col++;

                sd = convertIntToHexa(num);
            }
        }

        public string xor_numbers(string num1, string num2)
        {

            int len1 = num1.Count(), len2 = num2.Count();
            int idx1 = num1.Count(), idx2 = num2.Count();

            if (len2 < len1)
            {
                len1 = num2.Count();
                len2 = num1.Count();
            }

            int[] digits = new int[len2];
            for (int i = 0; i < len1; i++)
            {
                idx1--; 
                idx2--;

                if (num1[idx1] == num2[idx2])
                    digits[i] = 0;
                else
                    digits[i] = 1;
            }

            if (len2 == len1)
                return string.Join("", digits);

            if (num1.Count() > num2.Count())
            {
                for (int i = len1; i < len2; i++)
                {
                    idx1--;
                    if (num1[idx1] == '0')
                        digits[i] = 0;
                    else
                        digits[i] = 1;

                }
                return string.Join("", digits);
            }

            for (int i = len1; i < len2; i++)
            {
                idx2--;
                if (num2[idx2] == '0')
                    digits[i] = 0;
                else
                    digits[i] = 1;

            }
            return string.Join("", digits);
        }

        public void keyExpansion(string cipherText)
        {
            int idx = 2;
            for (int col = 4; col > 0; col--)
            {
                matrix[(idx / 2) - 1, 0] = Convert.ToInt32(cipherText.Substring(idx, 2), 16);
                idx += 2;
            }

            for (int col = 4; col > 0; col--)
            {
                matrix[((idx / 2) - 1) - 4, 1] = Convert.ToInt32(cipherText.Substring(idx, 2), 16);
                idx += 2;
            }

            for (int col = 4; col > 0; col--)
            {
                matrix[((idx / 2) - 1) - 8, 2] = Convert.ToInt32(cipherText.Substring(idx, 2), 16);
                idx += 2;
            }

            for (int col = 4; col > 0; col--)
            {
                matrix[((idx / 2) - 1) - 12, 3] = Convert.ToInt32(cipherText.Substring(idx, 2), 16);
                idx += 2;
            }
        }

        public override string Decrypt(string cipherText, string key)
        {
            string hexa;
            string text;

            getKeySchedule(key);
            keyExpansion(cipherText);

            //add round key (last key)
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    hexa = keySchedule[i, j + ((9 + 1) * 4)].Substring(0, keySchedule[i, j + ((9 + 1) * 4)].Count());
                    matrix[i, j] = matrix[i, j] ^ Convert.ToInt32(hexa, 16);
                }
            }

            reverseShiftRowsTransformation();
            reverseSubBytesTransformation();
            
            text = "" + convert();

            for (int idx = 0; idx < 9; idx++)
            {
                //add round key
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        hexa = keySchedule[i, j + ((8 - idx + 1) * 4)].Substring(0, keySchedule[i, j + ((8 - idx + 1) * 4)].Count());
                        matrix[i, j] = matrix[i, j] ^ Convert.ToInt32(hexa, 16);
                    }
                }
                

                reverseMixColumns();
                

                reverseShiftRowsTransformation();
                

                reverseSubBytesTransformation();
                
            }

            //add round key
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    hexa = keySchedule[i, j + ((0) * 4)].Substring(0, keySchedule[i, j + ((0) * 4)].Count());
                    matrix[i, j] = matrix[i, j] ^ Convert.ToInt32(hexa, 16);
                }
            }

           
            return convert();
        }

        public override string Encrypt(string plainText, string key)
        {
            string hexa1, hexa2;

            getKeySchedule(key);

            // round #1
            firstRound(plainText, key);

            // round #2 -> round #10
            for (int i = 0; i < 10; i++)
            {

                subBytesTransformation();
                shiftRowsTransformation();
                
                if(i!=9) // each round except last round
                    mixColumnsTransformation();

                // adding round key transformation
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if(i!=9)
                            hexa1 = afterColumnMix[j, k].Substring(0, afterColumnMix[j, k].Count());
                        else
                            hexa1 = afterSubBytes[j, k].Substring(0, afterSubBytes[j, k].Count());
                        
                        hexa2 = keySchedule[j, k + ((i + 1) * 4)].Substring(0, keySchedule[j, k + ((i + 1) * 4)].Count());
                        matrix[j, k] = Convert.ToInt32(hexa1, 16) ^ Convert.ToInt32(hexa2, 16);

                    }
                }
               
            }
            return convert();
        }     
        
    }
}
