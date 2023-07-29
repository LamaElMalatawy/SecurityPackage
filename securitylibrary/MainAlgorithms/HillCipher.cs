using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        string dict = "abcdefghijklmnopqrstuvwxyz";

        //Helper Functions
        public static int GCD(int num1, int num2)
        {
            while (num2 != 0)
            {
                int temp = num2;
                num2 = num1 % num2;
                num1 = temp;
            }
            return num1;
        }

        public int[,] inverse_key_matrix(int[,] key, int b, int[,] D)
        {
            int[,] res = new int[3, 3];

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {

                    int s = (int)(b * Math.Pow(-1, (i + j)) * D[i, j] % 26);
                    if (s < 0)
                        s += 26;
                    res[j, i] = s;
                }
            }
            return res;
        }


        //Main Functions
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {

            //Initialization
            int size = cipherText.Count();
            List<int> k = new List<int>();
            int alphabeticlen = 26;
            bool iskeyfound = true;

            for (int i = 0; i < alphabeticlen; i++)
            {
                for (int j = 0; j < alphabeticlen; j++)
                {
                    for (int m = 0; m < alphabeticlen; m++)
                    {
                        for (int f = 0; f < alphabeticlen; f++)
                        {

                            k.Add(i); k.Add(j); k.Add(m); k.Add(f);
                            //Passing our key to the encrypt function
                            List<int> cipher = Encrypt(plainText, k);

                            iskeyfound = true;
                            for (int n = 0; n < size; n++)
                                if (cipher[n] != cipherText[n])
                                {
                                    iskeyfound = false;
                                    break;
                                }
                            if (iskeyfound)
                                break;

                            k.Clear();
                        }
                        if (iskeyfound)
                            break;
                    }
                    if (iskeyfound)
                        break;
                }
                if (iskeyfound)
                    break;
            }
            if (!iskeyfound)
                throw new InvalidAnlysisException();

            return k;
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            //Initialization
            int cnt = key.Count;
            int cipherTextSize;
            int size;
            int[,] keyMat;
            int determinent = 0;
            List<List<int>> cipher = new List<List<int>>();
            List<int> answer = new List<int>();

            if (cnt % 3 == 0)
            {
                cipherTextSize = (cipherText.Count / 3);
                size = 3;

                for (int i = 0; i < 3; i++)
                {
                    cipher.Add(new List<int>());
                    for (int j = i; j < cipherText.Count; j += size)
                    {
                        cipher[i].Add(cipherText[j]);

                    }

                }
                keyMat = new int[3, 3] {
                         {key[0],key[1],key[2]} ,
                         {key[3],key[4],key[5]} ,
                         {key[6],key[7],key[8]}
               };

                int[,] D = new int[3, 3];
                D[0, 0] = keyMat[1, 1] * keyMat[2, 2] - keyMat[2, 1] * keyMat[1, 2];
                D[0, 1] = keyMat[1, 0] * keyMat[2, 2] - keyMat[1, 2] * keyMat[2, 0];
                D[0, 2] = keyMat[1, 0] * keyMat[2, 1] - keyMat[1, 1] * keyMat[2, 0];
                D[1, 0] = keyMat[0, 1] * keyMat[2, 2] - keyMat[0, 2] * keyMat[2, 1];
                D[1, 1] = keyMat[0, 0] * keyMat[2, 2] - keyMat[0, 2] * keyMat[2, 0];
                D[1, 2] = keyMat[0, 0] * keyMat[2, 1] - keyMat[0, 1] * keyMat[2, 0];
                D[2, 0] = keyMat[0, 1] * keyMat[1, 2] - keyMat[0, 2] * keyMat[1, 1];
                D[2, 1] = keyMat[0, 0] * keyMat[1, 2] - keyMat[0, 2] * keyMat[1, 0];
                D[2, 2] = keyMat[0, 0] * keyMat[1, 1] - keyMat[0, 1] * keyMat[1, 0];

                // step 1
                determinent = keyMat[0, 0] * D[0, 0] - keyMat[0, 1] * D[0, 1] + keyMat[0, 2] * D[0, 2];
                determinent %= 26;
                if (determinent > 0)
                {
                    determinent = 26 - determinent;
                }
                float c = 0.1f;
                float x = 1;
                while ((int)c != c)
                {
                    c = x / (float)Math.Abs(determinent);
                    x += 26;
                }
                int b = 26 - (int)c;


                int[,] result = inverse_key_matrix(keyMat, b, D);
                int sum = 0;
                for (int j = 0; j < cipherTextSize; j++)
                {
                    for (int i = 0; i < size; i++)
                    {
                        for (int m = 0; m < size; m++)
                        {
                            sum += (result[i, m] * cipher[m][j]);
                        }
                        answer.Add((sum) % 26);
                        sum = 0;
                    }
                }

            }
            else
            {
                cipherTextSize = (cipherText.Count / 2);
                size = 2;
                for (int i = 0; i < 2; i++)
                {
                    cipher.Add(new List<int>());
                    for (int j = i; j < cipherText.Count; j += size)
                    {
                        cipher[i].Add(cipherText[j]);
                    }
                }

                // step 1
                determinent = (key[3] * key[0]) - (key[1] * key[2]);
                determinent %= 26;

                keyMat = new int[2, 2] {

                         {key[0],key[1]} ,
                         {key[2],key[3]} ,
                };

                //step 2 get b
                float c = 0.1f;
                int x = 1;

                while ((int)c != c)
                {
                    c = x / Math.Abs(determinent);
                    x += 26;
                }
                int b = 26 - (int)c;

                // step 1 continue.
                if (determinent < 0)
                    determinent += 26;
                int[,] D = new int[2, 2];
                D[0, 0] = keyMat[1, 1];
                D[0, 1] = keyMat[1, 0];
                D[1, 0] = keyMat[0, 1];
                D[1, 1] = keyMat[0, 0];

                int[,] res = new int[2, 2];
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        int s = (int)(b * Math.Pow(-1, (i + j)) * D[i, j] % 26);
                        if (s < 0)
                            s += 26;
                        res[j, i] = s;
                    }
                }
                int gcd = GCD(26, determinent);
                if (gcd != 1)
                    throw new SystemException("GCD must be 1");

                int sum = 0;
                for (int j = 0; j < cipherTextSize; j++)
                {
                    for (int i = 0; i < size; i++)
                    {
                        for (int m = 0; m < size; m++)
                        {
                            sum += (res[i, m] * cipher[m][j]);
                        }
                        answer.Add((sum) % 26);
                        sum = 0;
                    }
                }
            }
            return answer;
        }

        public string Decrypt(string cipherText, string key)
        {
            List<int> cT = new List<int>();
            List<int> k = new List<int>();

            for (int i = 0; i < cipherText.Length; i++)
            {
                cT.Add(dict.IndexOf(cipherText[i]));
            }

            for (int i = 0; i < key.Length; i++)
            {
                k.Add(dict.IndexOf(key[i]));
            }

            List<int> ans = Decrypt(cT, k);
            string res = "";

            for (int i = 0; i < ans.Count; i++)
            {
                res += dict[ans[i]];
            }

            return res;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //Initialization
            int n = key.Count;
            int plainTextSize;
            int sz;
            int[,] k;
            List<List<int>> pT = new List<List<int>>();
            List<int> ans;
            int sum = 0;


            if (n % 3 == 0)
            {
                k = new int[3, 3] {
                         {key[0],key[1],key[2]} ,
                         {key[3],key[4],key[5]} ,
                         {key[6],key[7],key[8]}
                };

                plainTextSize = (plainText.Count / 3);
                sz = 3;

                for (int i = 0; i < 3; i++)
                {
                    pT.Add(new List<int>());
                    for (int j = i; j < plainText.Count; j += sz)
                    {
                        pT[i].Add(plainText[j]);

                    }

                }
            }
            else
            {
                k = new int[2, 2] {
                         {key[0],key[1]} ,
                         {key[2],key[3]} ,
                };

                plainTextSize = (plainText.Count / 2);
                sz = 2;

                for (int i = 0; i < 2; i++)
                {
                    pT.Add(new List<int>());
                    for (int j = i; j < plainText.Count; j += sz)
                    {
                        pT[i].Add(plainText[j]);

                    }

                }

            }

            ans = new List<int>();
            sum = 0;
            for (int j = 0; j < plainTextSize; j++)
            {
                for (int i = 0; i < sz; i++)
                {
                    for (int m = 0; m < sz; m++)
                    {
                        sum += (k[i, m] * pT[m][j]);
                    }
                    ans.Add((sum) % 26);
                    sum = 0;
                }
            }

            return ans;
        }

        public string Encrypt(string plainText, string key)
        {
            List<int> pT = new List<int>();
            List<int> k = new List<int>();

            for (int i = 0; i < plainText.Length; i++)
            {
                pT.Add(dict.IndexOf(plainText[i]));
            }

            for (int i = 0; i < key.Length; i++)
            {
                k.Add(dict.IndexOf(key[i]));
            }

            List<int> ans = Encrypt(pT, k);
            string res = "";

            for (int i = 0; i < ans.Count; i++)
            {
                res += dict[ans[i]];
            }

            return res;

        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {

            //Initialization
            List<int> key = new List<int>();
            int size = plain3.Count;
            int alphabeticlen = 26;
            int sz = 3;
            bool iskeyfound;
            int cipher;

            for (int m = 0; m < sz; m++)
                for (int i = 0; i < alphabeticlen; i++)
                    for (int j = 0; j < alphabeticlen; j++)
                        for (int k = 0; k < alphabeticlen; k++)
                        {
                            iskeyfound = true;
                            for (int l = 0; l < size - 1; l += sz)
                            {
                                cipher = ((i * plain3[l]) + (j * plain3[l + 1]) + (k * plain3[l + 2])) % alphabeticlen;
                                if (cipher != cipher3[m + l])
                                {
                                    iskeyfound = false;
                                    break;
                                }
                            }
                            if (iskeyfound)
                            {
                                key.Add(i); key.Add(j); key.Add(k);
                            }
                        }

            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
