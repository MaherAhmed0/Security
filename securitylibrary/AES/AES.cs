using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            // Remove "0x" from strings
            if (plainText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                plainText = plainText.Substring(2);
            }
            if (key.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                key = key.Substring(2);
            }
            string[,] plainMatrix = new string[4, 4];
            string[,] keyMatrix = new string[4, 4];
            plainMatrix = matrixGeneration(plainText);
            keyMatrix = matrixGeneration(key);
            plainMatrix = AddRoundKey(plainMatrix, keyMatrix);            
            plainMatrix = SubBytes(plainMatrix);
            plainMatrix = shiftRows(plainMatrix);
            plainMatrix = MixColumns(plainMatrix);
            return plainText;
        }
       
        public string[,] SubBytes(string[,] plainText)
        {
            string[,] sbox = new string[16, 16] {
                { "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
      { "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"},
      { "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"},
     { "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
      { "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
      { "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
      { "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
      { "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
      { "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
     { "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
     { "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
     { "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
     { "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
      { "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
      { "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
      { "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"}
            };
            string[,] text = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string hexValue = plainText[i, j];
                    int row = int.Parse("0" + hexValue[0], System.Globalization.NumberStyles.HexNumber);
                    int col = int.Parse("0" + hexValue[1], System.Globalization.NumberStyles.HexNumber);
                    text[i,j] = sbox[row, col];
                }
            }
            return text;
        }
        public string[,] matrixGeneration(string plainText)
        {
            string[] plain = new string[plainText.Length / 2];
            for(int i = 0; i < plainText.Length; i += 2)
            {
                plain[i / 2] = plainText.Substring(i, 2); 
            }
            string[,] matrix = new string[4,4];
            int k = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix[j, i] = plain[k];
                    k++;
                }
            }
            return matrix;
        }
        public string[,] shiftRows(string[,] plainText)
        {
            // ShiftRows transformation
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    string temp = plainText[i, 0];
                    for (int k = 1; k < 4; k++)
                    {
                        plainText[i, k - 1] = plainText[i, k];
                    }
                    plainText[i, 3] = temp;
                }
            }
            // Return the shifted matrix
            return plainText;
        }
        public string[,] AddRoundKey(string[,] plainText, string[,] key)
        {
            // Create a new 4x4 matrix to hold the result
            string[,] result = new string[4, 4];

            // XOR each byte of the plainText matrix with the corresponding byte of the key matrix
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // Convert the byte strings to integers and perform XOR
                    int plainByte = Convert.ToInt32(plainText[i, j], 16);
                    int keyByte = Convert.ToInt32(key[i, j], 16);
                    int resultByte = plainByte ^ keyByte;

                    // Convert the result back to a string and store in the result matrix
                    result[i, j] = resultByte.ToString("X2");
                }
            }

            // Return the resulting matrix
            return result;
        }

        public static string[,] MixColumns(string[,] matrix)
        {
            int[,] coefficients = new int[4, 4]
            {
        { 0x02, 0x03, 0x01, 0x01 },
        { 0x01, 0x02, 0x03, 0x01 },
        { 0x01, 0x01, 0x02, 0x03 },
        { 0x03, 0x01, 0x01, 0x02 }
            };

            string[,] result = new string[4, 4];
            for (int col = 0; col < 4; col++)
            {
                int[] column = new int[4];
                for (int row = 0; row < 4; row++)
                {
                    column[row] = Convert.ToInt32(matrix[row, col], 16);
                }

                int[] temp = new int[4];
                for (int row = 0; row < 4; row++)
                {
                    int dot = 0;
                    for (int i = 0; i < 4; i++)
                    {
                        dot ^= GF28Multiply(coefficients[row, i], column[i]);
                    }
                    temp[row] = dot;
                }

                for (int row = 0; row < 4; row++)
                {
                    result[row, col] = temp[row].ToString("X2");
                }
            }

            return result;
        }

        private static int GF28Multiply(int a, int b)
        {
            int p = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                bool hiBitSet = (a & 0x80) != 0;
                a <<= 1;
                if (hiBitSet)
                {
                    a ^= 0x11b; // reducing modulo x^8 + x^4 + x^3 + x + 1
                }

                b >>= 1;
            }
            return p;
        }

    }
}