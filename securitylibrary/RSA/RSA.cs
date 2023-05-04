using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            BigInteger C = BigInteger.ModPow(M, e, n);
            return (int)C;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            ExtendedEuclid E = new ExtendedEuclid();
            int d = E.GetMultiplicativeInverse(e, phi);
            BigInteger M = BigInteger.ModPow(C, d, n);
            return (int)M;
        }
    }
}
