using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        char[,] matrix = new char[10000,10000] ;
        public int Analyse(string plainText, string cipherText)
        {
            
            string newCipher;
            int res = 0;
            for(int i = 1; i < plainText.Length; i++)
            {
                newCipher = Encrypt(plainText, i);
                if (newCipher.Equals(cipherText.ToLower()))
                {
                    res = i;
                    break;
                }

            }
            Console.WriteLine(res);
            return res;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();

            string PlainText = "";
            int k = 0;
            if(cipherText.Length%key == 0)
            {
                for (int i = 0; i < key; i++)
                {
                    for (int j = 0; j < Math.Ceiling((double)(cipherText.Length / key)) && k < cipherText.Length; j++)
                    {
                        matrix[j, i] = cipherText[k];
                        Console.Write(matrix[j, i]);
                        k++;

                    }
                    Console.WriteLine();
                }
                Console.WriteLine(cipherText);
            }
            else
            {
                for (int i = 0; i < key; i++)
                {
                    for (int j = 0; j <= Math.Ceiling((double)(cipherText.Length / key)) && k < cipherText.Length; j++)
                    {
                        matrix[j, i] = cipherText[k];
                        Console.Write(matrix[j, i]);
                        k++;

                    }
                    Console.WriteLine();
                }
                Console.WriteLine(cipherText);
            }

            for (int i = 0; i <= Math.Ceiling((double)(cipherText.Length / key)) ; i++)
            {
                for (int j = 0; j < key ; j++)
                {
                    PlainText += matrix[i, j];                    
                }
                //Console.WriteLine();
            }
            Console.WriteLine(PlainText);
            
            return PlainText;
        }

        public string Encrypt(string plainText, int key)
        {
            //matrix = new char[key, plainText.Length];   
            int k = 0;
            for (int i = 0; i < Math.Ceiling((double)(plainText.Length / key)) && k < plainText.Length; i++)
            {
                for (int j = 0; j < key && k < plainText.Length; j++)
                {
                    if (plainText[k] == ' ')
                        continue;
                    Console.Write(matrix[j, i]);
                    matrix[j,i] = plainText[k];
                    k++;
                }
            }

          
            string cipherText="";
            //throw new NotImplementedException();
            // plain text :  computer science   key = 2 
            // cipher text : cmuesine optrcec
            int cnt = 0;
            for(int i = 0; i<plainText.Length && cnt < key; i++)
            {
                cnt++;
                for(int j = i; j<plainText.Length; j += key)
                {
                    if (plainText[j] == ' ')
                        continue;
                    cipherText += plainText[j];

                }
            }

            //Console.WriteLine(cipherText);
            //Console.WriteLine("ranaaaaaaaaaaaaa");
            return cipherText;
        }
    }
}
