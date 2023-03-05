using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public int Determinant(int[,] matrix,int m)
        {
            if (m == 2)
            {
                return matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];
            }
            else if (m == 3)
            {
                return matrix[0, 0] * (matrix[1, 1] * matrix[2, 2] - matrix[1, 2] * matrix[2, 1])
                    - matrix[0, 1] * (matrix[1, 0] * matrix[2, 2] - matrix[1, 2] * matrix[2, 0])
                    + matrix[0, 2] * (matrix[1, 0] * matrix[2, 1] - matrix[1, 1] * matrix[2, 0]);
            }
            return 0;
        }

        public int GCD(int num1, int num2)
        {
            int Remainder;

            while (num2 != 0)
            {
                Remainder = num1 % num2;
                num1 = num2;
                num2 = Remainder;
            }

            return num1;
        }



        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();
            int a = -1;
            int b = -1;
            int c = -1;
            int d = -1;
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (((i * plainText[0] + j * plainText[1]) % 26 == cipherText[0])&& ((i * plainText[2] + j * plainText[3]) % 26 == cipherText[2]))
                    {    
                        a = i;
                        b = j;
                        break;
                    }
                }
                if (a != -1 && b != -1)
                {
                    break;
                }
            }

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (((i * plainText[0] + j * plainText[1]) % 26 == cipherText[1])&& ((i * plainText[2] + j * plainText[3]) % 26 == cipherText[3]))
                    {
                        c = i;
                        d = j;
                        break;
                    }
                }
                if (c != -1 && d != -1)
                {
                    break;
                }
            }
            if (a == -1 || b == -1 || c == -1 || d == -1)
            {
                throw new InvalidAnlysisException();
            }
            else
            {

                key.Add(a);
                key.Add(b);
                key.Add(c);
                key.Add(d);
                return key;
            }
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> Pt = new List<int>();
            int m = (int)Math.Sqrt((double)key.Count);
            int[,] keyArray2d = new int[m, m];
            int[,] invKey2dArr = new int[m, m];
            int[,] invKey2dArrT = new int[m, m];
            int determinant=0;
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    keyArray2d[i, j] = key[i * m + j];
                    if (keyArray2d[i, j] < 0 || keyArray2d[i, j] > 26)
                    {
                        //throw new NotImplementedException();
                    }
                }
            }

            if (m == 2)
            {
                //determinant = keyArray2d[0, 0] * keyArray2d[1, 1] - keyArray2d[0, 1] * keyArray2d[1, 0];
                determinant = Determinant(keyArray2d, m);
                if (determinant == 0)
                {
                    throw new NotImplementedException();
                }
                invKey2dArr[0, 0] = (1 / determinant) * keyArray2d[1, 1];
                invKey2dArr[1, 1] = (1 / determinant) * keyArray2d[0, 0];
                invKey2dArr[0, 1] = (1 / determinant) * -keyArray2d[0, 1];
                invKey2dArr[1, 0] = (1 / determinant) * -keyArray2d[1, 0];
            }
            else if (m == 3)
            {
                determinant = Determinant(keyArray2d, m);
                if (determinant == 0)
                {
                    //throw new NotImplementedException();
                }
                determinant = (Math.Abs(determinant * 26) + determinant) % 26;
                int b = 1;
                while (true)
                {
                    if ((b * determinant) % 26 == 1)
                    {
                        break;
                    }
                    b++;
                }
                

                invKey2dArr[0, 0] = (keyArray2d[1, 1] * keyArray2d[2, 2] - keyArray2d[1, 2] * keyArray2d[2,1])*(b * (int)Math.Pow((double)-1, (double)(0)));
                invKey2dArr[0, 1] = (keyArray2d[1, 0] * keyArray2d[2, 2] - keyArray2d[1, 2] * keyArray2d[2, 0]) * (b * (int)Math.Pow((double)-1, (double)(1)));
                invKey2dArr[0, 2] = (keyArray2d[1, 0] * keyArray2d[2, 1] - keyArray2d[1, 1] * keyArray2d[2, 0]) * (b * (int)Math.Pow((double)-1, (double)(2)));
                invKey2dArr[1, 0] = (keyArray2d[0, 1] * keyArray2d[2, 2] - keyArray2d[0, 2] * keyArray2d[2, 1]) * (b * (int)Math.Pow((double)-1, (double)(1)));
                invKey2dArr[1, 1] = (keyArray2d[0, 0] * keyArray2d[2, 2] - keyArray2d[0, 2] * keyArray2d[2, 0]) * (b * (int)Math.Pow((double)-1, (double)(2)));
                invKey2dArr[1, 2] = (keyArray2d[0, 0] * keyArray2d[2, 1] - keyArray2d[0, 1] * keyArray2d[2, 0]) * (b * (int)Math.Pow((double)-1, (double)(3)));
                invKey2dArr[2, 0] = (keyArray2d[0, 1] * keyArray2d[1, 2] - keyArray2d[1, 1] * keyArray2d[0, 2]) * (b * (int)Math.Pow((double)-1, (double)(2)));
                invKey2dArr[2, 1] = (keyArray2d[0, 0] * keyArray2d[1, 2] - keyArray2d[1, 0] * keyArray2d[0, 2]) * (b * (int)Math.Pow((double)-1, (double)(3)));
                invKey2dArr[2, 2] = (keyArray2d[0, 0] * keyArray2d[1, 1] - keyArray2d[0, 1] * keyArray2d[1, 0]) * (b * (int)Math.Pow((double)-1, (double)(4)));

                for(int i = 0; i < m; i++)
                {
                    for(int j=0; j<m; j++)
                    {
                        invKey2dArr[i, j] = (Math.Abs(invKey2dArr[i, j] * 26) + invKey2dArr[i, j]) % 26;
                    }
                }
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        invKey2dArrT[i, j] = invKey2dArr[j, i];
                    }
                }
                
                invKey2dArr = invKey2dArrT;
                
                

            }




            int gcd = GCD(determinant, 26);
            if (Math.Abs(gcd) != 1)
            {
                throw new NotImplementedException();
            }



            for (int i = 0; i < cipherText.Count; i += m)
            {
                for (int j = 0; j < m; j++)
                {
                    int z = i;
                    int product = 0;
                    for (int x = 0; x < m; x++)
                    {
                        product += cipherText[z] * invKey2dArr[j, x];
                        z++;
                    }
                    Pt.Add(product % 26);
                }
            }
            for(int i = 0; i < Pt.Count; i++)
            {
                if (Pt[i] < 0)
                {
                    Pt[i] += 26;
                }
            }

            return Pt;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherText = new List<int>();
            int m = (int)Math.Sqrt((double)key.Count);
            int[,] keyArray2d = new int[m, m];
            for(int i = 0; i < m; i++)
            {
                for(int j = 0; j < m; j++)
                {
                    keyArray2d[i, j] = key[i * m + j];
                }
            }
            for (int i = 0; i < plainText.Count;i+=m)
            {
                for(int j = 0; j < m; j++)
                {
                    int z = i;
                    int product = 0;
                    for(int x = 0; x < m; x++)
                    {
                        product +=plainText[z] * keyArray2d[j, x];
                        z++;
                    }
                    cipherText.Add(product%26);
                }
            }
            return cipherText;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<int> key = new List<int>();
            int[,] keyarr = new int[3,3];
            for(int x = 0; x < 3; x++)
            {
                keyarr[x,0] = -1;
                keyarr[x, 1] = -1;
                keyarr[x, 2] = -1;
            }

            for (int x = 0; x < 3; x++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            if (((j * plain3[0] + k * plain3[1] + l * plain3[2]) % 26 == cipher3[x])
                                && ((j * plain3[3] + k * plain3[4] + l * plain3[5]) % 26 == cipher3[x+3])
                                && ((j * plain3[6] + k * plain3[7] + l * plain3[8]) % 26 == cipher3[x+6])
                                )
                            {
                                keyarr[x,0] = j;
                                keyarr[x,1] = k;
                                keyarr[x,2] = l;
                                break;
                            }
                        }
                        if (keyarr[x,0] != -1 && keyarr[x,1] != -1 && keyarr[x,2] != -1)
                        {
                            break;
                        }
                    }
                    if (keyarr[x,0] != -1 && keyarr[x,1] != -1 && keyarr[x,2] != -1)
                    {
                        break;
                    }
                }
            }

            for(int x = 0; x < 3; x++)
            {
                key.Add(keyarr[x,0]);
                key.Add(keyarr[x, 1]);
                key.Add(keyarr[x, 2]);
            }
            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
