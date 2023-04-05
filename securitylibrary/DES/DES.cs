using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
                return cipherText;
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

            string Binary_plainText = "";
            string Binary_key  = "";

            // Convert Strings to binary
            foreach (char c in plainText)
            {
                string binary = Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0');
                Binary_plainText += binary;
            }
            foreach (char c in key)
            {
                string binary = Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0');
                Binary_key += binary;
            }

            int[] PC1 = new int[] { 57, 49, 41, 33, 25, 17, 9,  1, 58, 50, 42, 34, 26, 18,
                                    10, 2,  59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36, 63,
                                    55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22, 14, 6,
                                    61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4 };

            string Permutated_Key_PC1 = "";

            // Permutate the key with PC_1
            for (int i = 0; i < PC1.Length; i++)
            {
                int bit_indx = PC1[i];
                Permutated_Key_PC1 += Binary_key[bit_indx];
            }

            // Divide the 56-bit long key to C_0 & D_0 
            string C_0 = Permutated_Key_PC1.Substring(0, 28);
            string D_0 = Permutated_Key_PC1.Substring(28, 28);

            int[] No_Left_Shifts = new int[] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

            // Createing 16 subkeys after the Left Shifts
            string C_1 = Shift_Rotate_Bits(C_0, No_Left_Shifts[0]);
            string D_1 = Shift_Rotate_Bits(D_0, No_Left_Shifts[0]);
            string K_1 = String.Concat(C_1, D_1);

            string C_2 = Shift_Rotate_Bits(C_1, No_Left_Shifts[1]);
            string D_2 = Shift_Rotate_Bits(D_1, No_Left_Shifts[1]);
            string K_2 = String.Concat(C_2, D_2);


            string C_3 = Shift_Rotate_Bits(C_2, No_Left_Shifts[2]);
            string D_3 = Shift_Rotate_Bits(D_2, No_Left_Shifts[2]);
            string K_3 = String.Concat(C_3, D_3);

            string C_4 = Shift_Rotate_Bits(C_3, No_Left_Shifts[3]);
            string D_4 = Shift_Rotate_Bits(D_3, No_Left_Shifts[3]);
            string K_4 = String.Concat(C_4, D_4);

            string C_5 = Shift_Rotate_Bits(C_4, No_Left_Shifts[4]);
            string D_5 = Shift_Rotate_Bits(D_4, No_Left_Shifts[4]);
            string K_5 = String.Concat(C_5, D_5);

            string C_6 = Shift_Rotate_Bits(C_5, No_Left_Shifts[5]);
            string D_6 = Shift_Rotate_Bits(D_5, No_Left_Shifts[5]);
            string K_6 = String.Concat(C_6, D_6);

            string C_7 = Shift_Rotate_Bits(C_6, No_Left_Shifts[6]);
            string D_7 = Shift_Rotate_Bits(D_6, No_Left_Shifts[6]);
            string K_7 = String.Concat(C_7, D_7);

            string C_8 = Shift_Rotate_Bits(C_7, No_Left_Shifts[7]);
            string D_8 = Shift_Rotate_Bits(D_7, No_Left_Shifts[7]);
            string K_8 = String.Concat(C_8, D_8);

            string C_9 = Shift_Rotate_Bits(C_8, No_Left_Shifts[8]);
            string D_9 = Shift_Rotate_Bits(D_8, No_Left_Shifts[8]);
            string K_9 = String.Concat(C_9, D_9);

            string C_10 = Shift_Rotate_Bits(C_9, No_Left_Shifts[9]);
            string D_10 = Shift_Rotate_Bits(D_9, No_Left_Shifts[9]);
            string K_10 = String.Concat(C_10, D_10);

            string C_11 = Shift_Rotate_Bits(C_10, No_Left_Shifts[10]);
            string D_11 = Shift_Rotate_Bits(D_10, No_Left_Shifts[10]);
            string K_11 = String.Concat(C_11, D_11);

            string C_12 = Shift_Rotate_Bits(C_11, No_Left_Shifts[11]);
            string D_12 = Shift_Rotate_Bits(D_11, No_Left_Shifts[11]);
            string K_12 = String.Concat(C_12, D_12);

            string C_13 = Shift_Rotate_Bits(C_12, No_Left_Shifts[12]);
            string D_13 = Shift_Rotate_Bits(D_12, No_Left_Shifts[12]);
            string K_13 = String.Concat(C_13, D_13);

            string C_14 = Shift_Rotate_Bits(C_13, No_Left_Shifts[13]);
            string D_14 = Shift_Rotate_Bits(D_13, No_Left_Shifts[13]);
            string K_14 = String.Concat(C_14, D_14);

            string C_15 = Shift_Rotate_Bits(C_14, No_Left_Shifts[14]);
            string D_15 = Shift_Rotate_Bits(D_14, No_Left_Shifts[14]);
            string K_15 = String.Concat(C_15, D_15);

            string C_16 = Shift_Rotate_Bits(C_15, No_Left_Shifts[15]);
            string D_16 = Shift_Rotate_Bits(D_15, No_Left_Shifts[15]);
            string K_16 = String.Concat(C_16, D_16);


            //int[] PC2 = new int[] { 14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12,
            //                        4,  26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55,
            //                        30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50,
            //                        36, 29, 32 };
            //int[] IP = new int[] {  58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20,
            //                        12, 4,  62, 54, 46, 38, 30, 22, 14, 6,  64, 56, 48, 40, 32,
            //                        24, 16, 8,  57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35,
            //                        27, 19, 11, 3,  61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47,
            //                        39, 31, 23, 15, 7 };
            //int[] E = new int[] {   32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10,
            //                        11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21,
            //                        20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30,
            //                        31, 32, 1 };

            return plainText;
        }
        static string Shift_Rotate_Bits(string Input, int Shift_Amount)
        {
            int Num = Convert.ToInt32(Input, 2);
            int Num_Bits = Input.Length;
            int Rotated_Num = ((Num << Shift_Amount) & ((1 << Num_Bits) - 1)) | (Num >> (Num_Bits - Shift_Amount)); // Shift the bits to the left by the shift amount
            string Rotated_Str = Convert.ToString(Rotated_Num, 2).PadLeft(Num_Bits, '0'); // Convert the rotated number back to a binary string
            return Rotated_Str;
        }
    }
}