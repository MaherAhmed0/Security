using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;
using SecurityLibrary.DiffieHellman;

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
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> result = new List<long>();
            BigInteger c1 = BigInteger.ModPow(alpha, k, q);
            result.Add((long)c1);
            BigInteger K = BigInteger.ModPow(y, k, q);
            long c2 = (long)K * m % q;
            result.Add(c2);
            return result;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            BigInteger K = BigInteger.ModPow(c1, x, q);
            ExtendedEuclid E = new ExtendedEuclid();
            int inverse = E.GetMultiplicativeInverse((int)K, q);
            int M = c2 * inverse % q;
            return M;
        }
    }
}
