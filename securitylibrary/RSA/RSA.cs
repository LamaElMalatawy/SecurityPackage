using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        int Q; int n;
        List<int> A = new List<int>();
        List<int> B = new List<int>();
        List<int> newB = new List<int>();

        public int get_d(int n, int e) // get the decryption key
        {
            A.Add(0); A.Add(1); A.Add(0); A.Add(n);
            B.Add(0); B.Add(0); B.Add(1); B.Add(e);
            newB.Add(0); newB.Add(0); newB.Add(0); newB.Add(0);

            for (int i = 0; B[3] != 1; i++)
            {

                Q = A[3] / B[3];
                for (int j = 1; j <= 3; j++)
                {
                    newB[j] = A[j] - Q * B[j];
                    A[j] = B[j];
                }
                B.Clear();
                B.AddRange(newB);
            }

            while (B[2] < 0)
            {
                B[2] += n;
            }

            return B[2];
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            n = q * p;
            double encryptedMsg = 1;
            double x = 1;

            for (int i = 0; i < e; i++)
            {
                encryptedMsg *= Math.Pow(M, (int)x);
                encryptedMsg %= Math.Pow(n, (int)x);
            }
            return (int)encryptedMsg;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            // prime factor which is dividing any prime number into 2 prime numbers.
            //  QN = Q(q*p) = (p - 1) * (q - 1)

            int qn = (p - 1) * (q - 1);
            int d = get_d(qn, e);
            return Encrypt(p, q, C, d);
        }
    }
}
