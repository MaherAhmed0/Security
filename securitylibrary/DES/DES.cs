using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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
                int bit_indx = PC1[i] - 1;
                Permutated_Key_PC1 += Binary_key[bit_indx];
            }

            // Divide the 56-bit long key to C_0 & D_0 
            string C_0 = Permutated_Key_PC1.Substring(0, 28);
            string D_0 = Permutated_Key_PC1.Substring(28, 28);

            int[] No_Left_Shifts = new int[] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

            // Createing 16 subkeys after the Left Shifts
            string C_1 = Shift_Rotate_Bits(C_0, No_Left_Shifts[0]);
            string D_1 = Shift_Rotate_Bits(D_0, No_Left_Shifts[0]);
            string C1D1 = String.Concat(C_1, D_1);
            
            string C_2 = Shift_Rotate_Bits(C_1, No_Left_Shifts[1]);
            string D_2 = Shift_Rotate_Bits(D_1, No_Left_Shifts[1]);
            string C2D2 = String.Concat(C_2, D_2);

            string C_3 = Shift_Rotate_Bits(C_2, No_Left_Shifts[2]);
            string D_3 = Shift_Rotate_Bits(D_2, No_Left_Shifts[2]);
            string C3D3 = String.Concat(C_3, D_3);

            string C_4 = Shift_Rotate_Bits(C_3, No_Left_Shifts[3]);
            string D_4 = Shift_Rotate_Bits(D_3, No_Left_Shifts[3]);
            string C4D4 = String.Concat(C_4, D_4);

            string C_5 = Shift_Rotate_Bits(C_4, No_Left_Shifts[4]);
            string D_5 = Shift_Rotate_Bits(D_4, No_Left_Shifts[4]);
            string C5D5 = String.Concat(C_5, D_5);

            string C_6 = Shift_Rotate_Bits(C_5, No_Left_Shifts[5]);
            string D_6 = Shift_Rotate_Bits(D_5, No_Left_Shifts[5]);
            string C6D6 = String.Concat(C_6, D_6);

            string C_7 = Shift_Rotate_Bits(C_6, No_Left_Shifts[6]);
            string D_7 = Shift_Rotate_Bits(D_6, No_Left_Shifts[6]);
            string C7D7 = String.Concat(C_7, D_7);

            string C_8 = Shift_Rotate_Bits(C_7, No_Left_Shifts[7]);
            string D_8 = Shift_Rotate_Bits(D_7, No_Left_Shifts[7]);
            string C8D8 = String.Concat(C_8, D_8);

            string C_9 = Shift_Rotate_Bits(C_8, No_Left_Shifts[8]);
            string D_9 = Shift_Rotate_Bits(D_8, No_Left_Shifts[8]);
            string C9D9 = String.Concat(C_9, D_9);

            string C_10 = Shift_Rotate_Bits(C_9, No_Left_Shifts[9]);
            string D_10 = Shift_Rotate_Bits(D_9, No_Left_Shifts[9]);
            string C10D10 = String.Concat(C_10, D_10);

            string C_11 = Shift_Rotate_Bits(C_10, No_Left_Shifts[10]);
            string D_11 = Shift_Rotate_Bits(D_10, No_Left_Shifts[10]);
            string C11D11 = String.Concat(C_11, D_11);

            string C_12 = Shift_Rotate_Bits(C_11, No_Left_Shifts[11]);
            string D_12 = Shift_Rotate_Bits(D_11, No_Left_Shifts[11]);
            string C12D12 = String.Concat(C_12, D_12);

            string C_13 = Shift_Rotate_Bits(C_12, No_Left_Shifts[12]);
            string D_13 = Shift_Rotate_Bits(D_12, No_Left_Shifts[12]);
            string C13D13 = String.Concat(C_13, D_13);

            string C_14 = Shift_Rotate_Bits(C_13, No_Left_Shifts[13]);
            string D_14 = Shift_Rotate_Bits(D_13, No_Left_Shifts[13]);
            string C14D14 = String.Concat(C_14, D_14);

            string C_15 = Shift_Rotate_Bits(C_14, No_Left_Shifts[14]);
            string D_15 = Shift_Rotate_Bits(D_14, No_Left_Shifts[14]);
            string C15D15 = String.Concat(C_15, D_15);

            string C_16 = Shift_Rotate_Bits(C_15, No_Left_Shifts[15]);
            string D_16 = Shift_Rotate_Bits(D_15, No_Left_Shifts[15]);
            string C16D16 = String.Concat(C_16, D_16);

            int[] PC2 = new int[] {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12,
                                    4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55,
                                    30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42,
                                    50, 36, 29, 32};
            string K_1 = "";
            string K_2 = "";
            string K_3 = "";
            string K_4 = "";
            string K_5 = "";
            string K_6 = "";
            string K_7 = "";
            string K_8 = "";
            string K_9 = "";
            string K_10 = "";
            string K_11 = "";
            string K_12 = "";
            string K_13 = "";
            string K_14 = "";
            string K_15 = "";
            string K_16 = "";

            for (int i = 0; i < PC2.Length; i++)
            {
                int bit_indx = PC2[i] - 1;
                K_1 += C1D1[bit_indx];
                K_2 += C2D2[bit_indx];
                K_3 += C3D3[bit_indx];
                K_4 += C4D4[bit_indx];
                K_5 += C5D5[bit_indx];
                K_6 += C6D6[bit_indx];
                K_7 += C7D7[bit_indx];
                K_8 += C8D8[bit_indx];
                K_9 += C9D9[bit_indx];
                K_10 += C10D10[bit_indx];
                K_11 += C11D11[bit_indx];
                K_12 += C12D12[bit_indx];
                K_13 += C13D13[bit_indx];
                K_14 += C14D14[bit_indx];
                K_15 += C15D15[bit_indx];
                K_16 += C16D16[bit_indx];
            }

            List<string> Keys = new List<string>();
            Keys.Add(K_1);
            Keys.Add(K_2);
            Keys.Add(K_3);
            Keys.Add(K_4);
            Keys.Add(K_5);
            Keys.Add(K_6);
            Keys.Add(K_7);
            Keys.Add(K_8);
            Keys.Add(K_9);
            Keys.Add(K_10);
            Keys.Add(K_11);
            Keys.Add(K_12);
            Keys.Add(K_13);
            Keys.Add(K_14);
            Keys.Add(K_15);
            Keys.Add(K_16);

            int[] IP = new int[] {  58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20,
                                    12, 4,  62, 54, 46, 38, 30, 22, 14, 6,  64, 56, 48, 40, 32,
                                    24, 16, 8,  57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35,
                                    27, 19, 11, 3,  61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47,
                                    39, 31, 23, 15, 7 };
            //Permutate Main text with IP
            string Permutated_Plain_Text = "";
            for (int i = 0; i < IP.Length; i++)
            {
                int bit_indx = IP[i] - 1;
                Permutated_Plain_Text += Binary_plainText[bit_indx];
            }

            List<string> Ls = new List<string>();
            List<string> Rs = new List<string>();
            string L_0 = Permutated_Plain_Text.Substring(0, 32);
            string R_0 = Permutated_Plain_Text.Substring(32, 32);
            Ls.Add(L_0);
            Rs.Add(R_0);

            for(int x = 0; x < 16; x++)
            {
                int[] E_selection = new int[] {32, 1, 2, 3, 4, 5 ,4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17,
                18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,28, 29, 30, 31, 32, 1};

                string Lnew = Rs[x];
                string E_Rcurrent = "";

                for (int i = 0; i < E_selection.Length; i++)
                {
                    int bit_indx = E_selection[i] - 1;
                    E_Rcurrent += Rs[x][bit_indx];
                }

                string xor = "";
                for (int i = 0; i < E_Rcurrent.Length; i++)
                {
                    if (Keys[x][i] == E_Rcurrent[i])
                    {
                        xor += "0";
                    }
                    else
                    {
                        xor += "1";
                    }
                }

                int[,] S1 = new int[,] {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}};

                int[,] S2 = new int[,] {
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}};            

                int[,] S3 = new int[,] {
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}};

                int[,] S4 = new int[,] {
                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}};            

                int[,] S5 = new int[,] {
                { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }};
            
                int[,] S6 = new int[,] {
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}};
            
                int[,] S7 = new int[,] {
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}};
            
                int[,] S8 = new int[,] {
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};
            
                List<int[,]> sboxes = new List<int[,]>();
                sboxes.Clear();
                sboxes.Add(S1);
                sboxes.Add(S2);
                sboxes.Add(S3);
                sboxes.Add(S4);
                sboxes.Add(S5);
                sboxes.Add(S6);
                sboxes.Add(S7);
                sboxes.Add(S8);

                int num;
                string colbin;
                int col;
                string rowbin;
                int row;
                int currents = 0;
                string sboxres = "";
                for (int i = 0; i < xor.Length; i += 6)
                {
                    rowbin = xor[i].ToString() + xor[i + 5].ToString();
                    colbin = xor.Substring((i + 1), 4);
                    row = Convert.ToInt32(rowbin, 2);
                    col = Convert.ToInt32(colbin, 2);

                    num = sboxes[currents][row, col];
                    currents++;
                    string binaryString = Convert.ToString(num, 2);
                    for (int j = 0; j < binaryString.Length; j++)
                    {
                        if (binaryString.Length < 4)
                        {
                            binaryString = "0" + binaryString;
                        }
                    }
                    sboxres += binaryString;
                }

                int[] P = new int[] {
                16, 7, 20, 21, 29, 12, 28, 17,
                1, 15, 23, 26, 5, 18, 31, 10,
                2, 8, 24, 14, 32, 27, 3, 9,
                19, 13, 30, 6, 22, 11, 4, 25};

                string F = "";
                for (int i = 0; i < P.Length; i++)
                {
                    int bit_indx = P[i] - 1;
                    F += sboxres[bit_indx];
                }

                string Rnew = "";

                for (int i = 0; i < F.Length; i++)
                {
                    if (F[i] == Ls[x][i])
                    {
                        Rnew += "0";
                    }
                    else
                    {
                        Rnew += "1";
                    }
                }
                Ls.Add(Lnew);
                Rs.Add(Rnew);
            }

            int[] IP1 = new int[] {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25 };
            
            string R16L16 = String.Concat(Rs[16], Ls[16]);
            string final = "";
            for (int i = 0; i < R16L16.Length; i++)
            {
                int bit_indx = IP1[i] - 1;
                final += R16L16[bit_indx];
            }
            string cypherText = Convert.ToInt64(final, 2).ToString("X");

            cypherText = "0x" + cypherText;
            return cypherText;
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