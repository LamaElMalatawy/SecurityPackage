using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>

        public static int mod(int mod, int num, int pow)
        {
            int result = 1;
            for (int i = 1; i <= pow; i++)
            {
                result = (result * num) % mod;
            }
            return result;
        }

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> cipherText = new List<long>();

            int K = mod(q, y, k);
            long C1 = mod(q, alpha, k);
            long C2 = mod(q, (K * m), 1);

            cipherText.Add(C1); 
            cipherText.Add(C2);
            return cipherText;
        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K = mod(q, c1, x);
            int k_power_negativeOne = new ExtendedEuclid().GetMultiplicativeInverse(K, q);
            int plainText = mod(q, (c2 * k_power_negativeOne), 1);
            return plainText;
        }
    }
}
