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

        Dictionary<char, string> dict_hexa_binary = new Dictionary<char, string>();
        Dictionary<string, char> dict_binary_hexa = new Dictionary<string, char>();
        int[] init_permutation;
        int[] perm_control_1;
        int[] perm_control_2;
        int[] e_bitselect;
        int[] sbox_permutation;
        int[] perm_inv;
        int[] round_shift;
        int[,,] sBox;
        int rounds = 16;
        public DES()
        {


            sBox = new int[,,]
               {
                    {
                        { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
                        { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
                        { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
                        { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
                    },
                    {
                        { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
                        { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
                        { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
                        { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
                    },
                    {
                        { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
                        { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
                        { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
                        { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
                    },
                    {
                        { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
                        { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
                        { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
                        { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
                    },
                    {
                        { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
                        { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
                        { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
                        { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
                    },
                    {
                        { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
                        { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
                        { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
                        { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
                    },
                    {
                        { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                        { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                        { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                        { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
                    },
                    {
                        { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
                        { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
                        { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
                        { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
                    }
           };

            // remove the values at 8th and it's multiples place
            // 8-16...
            // the key is converted from 64 to 56 bit key
            init_permutation = new int[]{
                58,50,42,34,26,18,10,2,
                60,52,44,36,28,20,12,4,
                62,54,46,38,30,22,14,6,
                64,56,48,40,32,24,16,8,
                57,49,41,33,25,17,9,1,
                59,51,43,35,27,19,11,3,
                61,53,45,37,29,21,13,5,
                63,55,47,39,31,23,15,7
                };

            perm_control_1 = new int[]{
                57,49,41,33,25,17,9,
                1,58,50,42,34,26,18,
                10,2,59,51,43,35,27,
                19,11,3,60,52,44,36,
                63,55,47,39,31,23,15,
                7,62,54,46,38,30,22,
                14,6,61,53,45,37,29,
                21,13,5,28,20,12,4};

            perm_control_2 = new int[]{
                14,17,11,24,1,5,
                3,28,15,6,21,10,
                23,19,12,4,26,8,
                16,7,27,20,13,2,
                41,52,31,37,47,55,
                30,40,51,45,33,48,
                44,49,39,56,34,53,
                46,42,50,36,29,32};

            round_shift = new int[] {
                1, 1, 2, 2,
                2, 2, 2, 2,
                1, 2, 2, 2,
                2, 2, 2, 1};

            e_bitselect = new int[]{
                32,1,2,3,4,5,4,5,
                6,7,8,9,8,9,10,11,
                12,13,12,13,14,15,16,17,
                16,17,18,19,20,21,20,21,
                22,23,24,25,24,25,26,27,
                28,29,28,29,30,31,32,1
                };

            sbox_permutation = new int[]{
                16,7,20,21,29,12,28,17,
                1,15,23,26,5,18,31,10,
                2,8,24,14,32,27,3,9,
                19,13,30,6,22,11,4,25
                };

            perm_inv = new int[]{
                40,8,48,16,56,24,64,32,
                39,7,47,15,55,23,63,31,
                38,6,46,14,54,22,62,30,
                37,5,45,13,53,21,61,29,
                36,4,44,12,52,20,60,28,
                35,3,43,11,51,19,59,27,
                34,2,42,10,50,18,58,26,
                33,1,41,9,49,17,57,25
                };

            dict_hexa_binary.Add('0', "0000"); dict_hexa_binary.Add('1', "0001"); dict_hexa_binary.Add('2', "0010"); dict_hexa_binary.Add('3', "0011");
            dict_hexa_binary.Add('4', "0100"); dict_hexa_binary.Add('5', "0101"); dict_hexa_binary.Add('6', "0110"); dict_hexa_binary.Add('7', "0111");
            dict_hexa_binary.Add('8', "1000"); dict_hexa_binary.Add('9', "1001"); dict_hexa_binary.Add('A', "1010"); dict_hexa_binary.Add('B', "1011");
            dict_hexa_binary.Add('C', "1100"); dict_hexa_binary.Add('D', "1101"); dict_hexa_binary.Add('E', "1110"); dict_hexa_binary.Add('F', "1111");

            dict_binary_hexa.Add("0000", '0'); dict_binary_hexa.Add("0001", '1'); dict_binary_hexa.Add("0010", '2'); dict_binary_hexa.Add("0011", '3');
            dict_binary_hexa.Add("0100", '4'); dict_binary_hexa.Add("0101", '5'); dict_binary_hexa.Add("0110", '6'); dict_binary_hexa.Add("0111", '7');
            dict_binary_hexa.Add("1000", '8'); dict_binary_hexa.Add("1001", '9'); dict_binary_hexa.Add("1010", 'A'); dict_binary_hexa.Add("1011", 'B');
            dict_binary_hexa.Add("1100", 'C'); dict_binary_hexa.Add("1101", 'D'); dict_binary_hexa.Add("1110", 'E'); dict_binary_hexa.Add("1111", 'F');
        }

        ////////////////    Our functions   /////////////////////
        public string HexatoBinary(string txt_in_hexa)
        {
            string txt_in_binary = "";
            for (int i = 0; i < txt_in_hexa.Length; i++)
            {
                char idx = txt_in_hexa[i];
                txt_in_binary += dict_hexa_binary[idx];
            }
            return txt_in_binary;
        }

        public string permutation(string key, int[] permTable)
        {
            string permutedKey = "";
            for (int i = 0; i < permTable.Length; i++)
            { // array is 0 based so we -1 to get index. 
                int idx = permTable[i] - 1;
                permutedKey += key[idx];
            }
            return permutedKey;
        }


        public List<string> left_circular_shift(string key_block_1, string key_block_2)
        {
            List<string> res = new List<string>();
            string whole_key = "";
            for (int i = 0; i < rounds; i++)
            {
                key_block_1 = key_block_1.Substring(round_shift[i]) + key_block_1.Substring(0, round_shift[i]);
                key_block_2 = key_block_2.Substring(round_shift[i]) + key_block_2.Substring(0, round_shift[i]);

                whole_key = permutation(key_block_1 + key_block_2, perm_control_2);
                res.Add(whole_key);
            }
            return res;
        }

        public string sBOX(string plain)
        {

            int sbox_idx = 0; int num = 6; string temp_plain = "";

            for (int i = 0; i < plain.Length; i += num)
            {
                string input_6bits = plain.Substring(i, num);

                string row_binary = input_6bits[0].ToString() + input_6bits[input_6bits.Length - 1].ToString();
                string col_binary = input_6bits.Substring(1, input_6bits.Length - 2);

                int row_idx = Convert.ToInt32(row_binary, 2);
                int col_idx = Convert.ToInt32(col_binary, 2);

                int result = sBox[sbox_idx, row_idx, col_idx];
                string result_binary = Convert.ToString(result, 2);

                result_binary = result_binary.PadLeft(4, '0');

                sbox_idx++;
                temp_plain += result_binary;
            }
            return temp_plain;
        }

        ////////////////    Main functions   /////////////////////
        public override string Encrypt(string plainText, string key)
        {
            string block1, block2;
            // start from second index to remove (0x)
            key = key.Substring(2);
            key = HexatoBinary(key);
            plainText = plainText.Substring(2);
            plainText = HexatoBinary(plainText);


            key = permutation(key, perm_control_1);

            block1 = key.Substring(0, 28);
            block2 = key.Substring(28);

            List<string> keys = left_circular_shift(block1, block2);


            plainText = permutation(plainText, init_permutation);

            block1 = plainText.Substring(0, 32);
            block2 = plainText.Substring(32);

            //16 different keys are used for each round (48-bit keys)
            for (int i = 0; i < rounds; i++)
            {
                // increase the size of one half to 48-bit text
                string perm_right = permutation(block2, e_bitselect);
                string temp_right = "";

                // xor between expanded/permutated right text and this round's key.
                for (int j = 0; j < perm_right.Length; j++)
                {
                    if (perm_right[j] == keys[i][j])
                        temp_right += "0";
                    else temp_right += "1";
                }

                temp_right = sBOX(temp_right); // betraga3o 32-bit tany
                temp_right = permutation(temp_right, sbox_permutation);

                string right_text = "";
                // xor between processed right text and the left text.
                for (int j = 0; j < temp_right.Length; j++)
                {
                    if (temp_right[j] == block1[j])
                        right_text += "0";
                    else
                        right_text += "1";
                }

                block1 = block2;
                block2 = right_text;
            }

            // ba3d ma benkhalas el 16 rounds benbadel el left wel right halves
            // w beykon da el cipher bs bel binary
            string bin_plain_txt = block2 + block1;
            bin_plain_txt = permutation(bin_plain_txt, perm_inv);

            string hexa_cipher = "";

            for (int i = 0; i < bin_plain_txt.Length; i += 4)
                hexa_cipher += dict_binary_hexa[bin_plain_txt.Substring(i, 4)];

            return "0x" + hexa_cipher;// da beykon el cipher text;
        }

        public override string Decrypt(string cipherText, string key)
        {
            // start from second index to remove (0x)
            string block1, block2;
            key = key.Substring(2);
            cipherText = cipherText.Substring(2);

            key = HexatoBinary(key);
            key = permutation(key, perm_control_1);

            block1 = key.Substring(0, 28);
            block2 = key.Substring(28);

            List<string> keys = left_circular_shift(block1, block2);

            keys.Reverse();

            cipherText = HexatoBinary(cipherText);
            cipherText = permutation(cipherText, init_permutation);

            block1 = cipherText.Substring(0, 32);
            block2 = cipherText.Substring(32);

            //16 different keys are used for each round (48-bit keys)
            for (int i = 0; i < rounds; i++)
            {
                // increase the size of one half to 48-bit text
                string perm_right = permutation(block2, e_bitselect);
                string temp_right = "";

                // xor between expanded/permutated right text and this round's key.
                for (int j = 0; j < perm_right.Length; j++)
                {
                    if (perm_right[j] == keys[i][j])
                        temp_right += "0";
                    else temp_right += "1";
                }

                temp_right = sBOX(temp_right); // betraga3o 32-bit tany
                temp_right = permutation(temp_right, sbox_permutation);

                string right_text = "";
                // xor between processed right text and the left text.
                for (int j = 0; j < temp_right.Length; j++)
                {
                    if (temp_right[j] == block1[j])
                        right_text += "0";
                    else
                        right_text += "1";
                }

                block1 = block2;
                block2 = right_text;
            }

            // ba3d ma benkhalas el 16 rounds benbadel el left wel right halves
            // w beykon da el cipher bs bel binary
            string bin_plain_txt = block2 + block1;
            bin_plain_txt = permutation(bin_plain_txt, perm_inv);

            string hexa_cipher = "";

            for (int i = 0; i < bin_plain_txt.Length; i += 4)
                hexa_cipher += dict_binary_hexa[bin_plain_txt.Substring(i, 4)];

            return "0x" + hexa_cipher;// da beykon el cipher text;

        }
    }
}
