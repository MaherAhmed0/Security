using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> keys = new List<int>();
            BigInteger ya = BigInteger.ModPow(alpha, xa, q);
            BigInteger yb = BigInteger.ModPow(alpha, xb, q);
            BigInteger kb = BigInteger.ModPow(ya, xb, q);
            BigInteger ka = BigInteger.ModPow(yb, xa, q);
            keys.Add((int)ka);
            keys.Add((int)kb);
            return keys;
        }
    }
}