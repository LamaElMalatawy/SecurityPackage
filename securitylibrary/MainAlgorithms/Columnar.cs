using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        static List<int[]> permutations = new List<int[]>();
        //w3resource
        private void Swap(ref int a, ref int b)
        {
            int tmp = a;
            a = b;
            b = tmp;
        }
        private void Permute(int[] list, int l, int r, int sz)
        {

            int i;
            if (l != r)
            {
                for (i = l; i <= r; i++)
                {
                    Swap(ref list[l], ref list[i]);
                    Permute(list, l + 1, r, sz);
                    Swap(ref list[l], ref list[i]);
                }
                
            }
            else if (l == r)
            {
                int[] arr = new int[sz];
                for (i = 0; i <= r; i++)
                {
                    arr[i] = list[i];
                }
                permutations.Add(arr);

            }
        }
        private void create_permutation()
        {

            for (int i = 2; i <= 7; i++)
            {
                int[] arr = new int[i];
                for (int j = 1; j <= i; j++)
                {
                    arr[j - 1] = j;
                }
                Permute(arr, 0, i - 1, i);

            }
        }
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            create_permutation();
            List<int> key = new List<int>();
            for (int i = 0; i < permutations.Count; i++)
            {
                key = permutations[i].ToList();
                if (plainText.ToLower().Equals(Decrypt(cipherText.ToLower(), key)))
                {
                    return key;
                }
            }
            Console.WriteLine(key);
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int len = cipherText.Length;
            if (len % key.Count != 0)
            {
                len += key.Count;
            }
            int rows = (int)Math.Ceiling((double)len / key.Count);
            string plainText = "";
            char[,] matrix = new char[1000, 1000];
            int idx;
            int cnt = 0;
            for (int i = 0; i < key.Count; i++)
            {
                idx = key.IndexOf(i + 1);
                for (int j = 0; j < rows; j++)
                {
                    if(cnt < cipherText.Length)
                    {
                        matrix[j, idx] = cipherText[cnt];
                        Console.Write(matrix[j, idx]);
                        cnt++;
                    }                                  
                }
                Console.WriteLine();
            }

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    plainText += matrix[i, j];
                }                
            }   

            Console.WriteLine(plainText);
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            // plain text :  Computer Science 
            // key = 1 3 4 2 5 
            // cipher text : CTIPSCOEEMRNUCE            
            string cipherText = "";
            int len = plainText.Length;
            int cols = key.Count;
            int rows = (int)Math.Ceiling((double)len / cols);
            char[,] matrix = new char[rows, cols];
            int cnt = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols && cnt < len; j++)
                {
                    if (plainText[cnt] == ' ')
                    {
                        continue;
                    }
                    matrix[i, j] = plainText[cnt];
                    Console.Write(matrix[i, j]);
                    cnt++;
                }
                Console.WriteLine();
            }
            int val = key.Min();
            int idx;
            for (int i = 0; i < cols ; i++)
            {
                idx = key.IndexOf(val);
                for (int j = 0; j < rows; j++)
                {
                    cipherText += matrix[j, idx];
                }
                val++;
                if (val > cols)
                    break;
            }
            Console.WriteLine(cipherText);
            return cipherText;
        }
    }
}