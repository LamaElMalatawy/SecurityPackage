using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        private int getModPow(int mod, int b, int power)
        {
            int ans = 1;

            for (int i = 1; i <= power; i++)
            {
                ans = (ans*b) % mod;
            }

            return ans;
        } 

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            List<int> keys = new List<int>();

            int ya = getModPow(q, alpha, xa);
            int yb = getModPow(q, alpha, xb);

            int ka = getModPow(q, yb, xa);
            int kb = getModPow(q, ya, xb);

            keys.Add(ka);
            keys.Add(kb);

            return keys;
        }
    }
}