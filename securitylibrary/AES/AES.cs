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
        string[,] sBox = new string[16, 16] {
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

        string[,] rcon = {
    {"01", "02", "04", "08", "10", "20", "40", "80", "1b", "36"},
    {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
    {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
    {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}
};
        int rconColumn = 0;
        public override string Decrypt(string cipherText, string key)
        {
            rconColumn = 0;
            string plain = "";
            // Remove "0x" from strings
            if (cipherText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                cipherText = cipherText.Substring(2);
            }
            if (key.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                key = key.Substring(2);
            }
            string[,] cipherMatrix = new string[4, 4];
            string[,] keyMatrix = new string[4, 4];
            string[,] tempkey = new string[4, 4];
            List<string[,]> keys = new List<string[,]> { };
            cipherMatrix = matrixGeneration(cipherText);
            keyMatrix = matrixGeneration(key);
            tempkey = keyMatrix;
            for (int i = 0; i < 10; i++)
            {
                keyMatrix = generateKeys(keyMatrix, rcon);
                keys.Add(keyMatrix);
            }
            cipherMatrix = AddRoundKey(cipherMatrix, keys[9]);

            for (int i = 9; i >= 0; i--)
            {
                if (i != 0)
                {
                    cipherMatrix = inverseShiftRows(cipherMatrix);
                    cipherMatrix = inverseSubBytes(cipherMatrix);
                    cipherMatrix = AddRoundKey(cipherMatrix, keys[i - 1]);
                    cipherMatrix = inverseMixColumns(cipherMatrix);
                }
                else
                {
                    cipherMatrix = inverseShiftRows(cipherMatrix);
                    cipherMatrix = inverseSubBytes(cipherMatrix);
                    cipherMatrix = AddRoundKey(cipherMatrix, tempkey);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain += cipherMatrix[j, i];
                }
            }
            plain = "0x" + plain;
            return plain;
        }

        public override string Encrypt(string plainText, string key)
        {

            string cipher = "";
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
            string[,] tempkey = new string[4, 4];
            List<string[,]> keys = new List<string[,]> { };
            tempkey = keyMatrix;
            for (int i = 0; i < 10; i++)
            {
                keyMatrix = generateKeys(keyMatrix, rcon);
                keys.Add(keyMatrix);
            }
            plainMatrix = AddRoundKey(plainMatrix, tempkey);
            for (int i = 0; i < 10; i++)
            {
                if (i != 9)
                {
                    plainMatrix = SubBytes(plainMatrix);
                    plainMatrix = shiftRows(plainMatrix);
                    plainMatrix = MixColumns(plainMatrix);
                    plainMatrix = AddRoundKey(plainMatrix, keys[i]);
                }
                else
                {
                    plainMatrix = SubBytes(plainMatrix);
                    plainMatrix = shiftRows(plainMatrix);
                    plainMatrix = AddRoundKey(plainMatrix, keys[i]);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    cipher += plainMatrix[j, i];
                }
            }
            cipher = "0x" + cipher;
            return cipher;
        }

        public string[,] SubBytes(string[,] plainText)
        {

            string[,] text = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string hexValue = plainText[i, j];
                    int row = int.Parse("0" + hexValue[0], System.Globalization.NumberStyles.HexNumber);
                    int col = int.Parse("0" + hexValue[1], System.Globalization.NumberStyles.HexNumber);
                    text[i, j] = sBox[row, col];
                }
            }
            return text;
        }

        public string[,] SubBytesColumn(string[,] column)
        {

            string[,] text = new string[4, 1];

            for (int i = 0; i < 4; i++)
            {
                string hexValue = column[i, 0];
                int row = int.Parse("0" + hexValue[0], System.Globalization.NumberStyles.HexNumber);
                int col = int.Parse("0" + hexValue[1], System.Globalization.NumberStyles.HexNumber);
                text[i, 0] = sBox[row, col];
            }
            return text;
        }

        public string[,] matrixGeneration(string plainText)
        {
            string[] plain = new string[plainText.Length / 2];
            for (int i = 0; i < plainText.Length; i += 2)
            {
                plain[i / 2] = plainText.Substring(i, 2);
            }
            string[,] matrix = new string[4, 4];
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
        public string[,] inverseShiftRows(string[,] cipherText)
        {
            // Inverse ShiftRows transformation
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    string temp = cipherText[i, 3];
                    for (int k = 3; k > 0; k--)
                    {
                        cipherText[i, k] = cipherText[i, k - 1];
                    }
                    cipherText[i, 0] = temp;
                }
            }
            // Return the inverse shifted matrix
            return cipherText;
        }
        public string[,] AddRoundKey(string[,] plainText, string[,] key)
        {
            // Create a new 4x4 matrix to hold the thirdColumn
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

                    // Convert the thirdColumn back to a string and store in the thirdColumn matrix
                    result[i, j] = resultByte.ToString("X2");
                }
            }

            // Return the resulting matrix
            return result;
        }

        public string[,] MixColumns(string[,] matrix)
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

        public static int GF28Multiply(int a, int b)
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

        public string[,] generateKeys(string[,] key, string[,] rcon)
        {
            string temp = key[0, 3];
            string[,] temp2 = new string[4, 1];
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                if (i == 0)
                {
                    string[,] thirdColumn = new string[4, 1];
                    string[,] firstColumn = new string[4, 1];
                    for (int j = 0; j < 4; j++)
                    {
                        temp2[j, 0] = key[j, 3];
                    }
                    for (int j = 0; j < 3; j++)
                    {
                        key[j, 3] = key[j + 1, 3];
                    }
                    key[3, 3] = temp;
                    for (int j = 0; j < 4; j++)
                    {
                        thirdColumn[j, 0] = key[j, 3];
                        firstColumn[j, 0] = key[j, i];
                    }
                    thirdColumn = SubBytesColumn(thirdColumn);

                    for (int j = 0; j < 4; j++)
                    {
                        // Convert the byte strings to integers and perform XOR
                        int firstByte = Convert.ToInt32(firstColumn[j, 0], 16);
                        int thirdByte = Convert.ToInt32(thirdColumn[j, 0], 16);
                        int r = Convert.ToInt32(rcon[j, rconColumn], 16);
                        int resultByte = firstByte ^ thirdByte ^ r;
                        // Convert the thirdColumn back to a string and store in the thirdColumn matrix
                        result[j, i] = resultByte.ToString("X2");
                    }
                    rconColumn++;
                }
                else
                {
                    string[,] thirdColumn = new string[4, 1];
                    string[,] firstColumn = new string[4, 1];
                    for (int j = 0; j < 4; j++)
                    {
                        if (i != 3)
                        {
                            firstColumn[j, 0] = key[j, i];
                        }
                        else
                        {
                            firstColumn[j, 0] = temp2[j, 0];
                        }
                        thirdColumn[j, 0] = result[j, i - 1];
                        // Convert the byte strings to integers and perform XOR
                        int firstByte = Convert.ToInt32(firstColumn[j, 0], 16);
                        int thirdByte = Convert.ToInt32(thirdColumn[j, 0], 16);
                        int resultByte = firstByte ^ thirdByte;
                        // Convert the thirdColumn back to a string and store in the thirdColumn matrix
                        result[j, i] = resultByte.ToString("X2");
                    }
                }
            }
            for (int j = 0; j < 4; j++)
            {
                key[j, 3] = temp2[j, 0];
            }
            return result;
        }

        public string[,] inverseSubBytes(string[,] plainText)
        {
            string[,] isBox = new string[16, 16] {
                { "52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB" },
                { "7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB" },
                { "54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E" },
                { "08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25" },
                { "72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92" },
                { "6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84" },
                { "90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06" },
                { "D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B" },
                { "3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73" },
                { "96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E" },
                { "47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B" },
                { "FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4" },
                { "1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F" },
                { "60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF" },
                { "A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61" },
                { "17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D" }
    };
            string[,] text = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string hexValue = plainText[i, j];
                    int row = int.Parse("0" + hexValue[0], System.Globalization.NumberStyles.HexNumber);
                    int col = int.Parse("0" + hexValue[1], System.Globalization.NumberStyles.HexNumber);
                    text[i, j] = isBox[row, col];
                }
            }
            return text;
        }

        public string[,] inverseMixColumns(string[,] matrix)
        {
            int[,] invCoefficients = new int[4, 4]
{
    { 0x0E, 0x0B, 0x0D, 0x09 },
    { 0x09, 0x0E, 0x0B, 0x0D },
    { 0x0D, 0x09, 0x0E, 0x0B },
    { 0x0B, 0x0D, 0x09, 0x0E }
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
                        dot ^= GF28Multiply(invCoefficients[row, i], column[i]);
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
    }
}