/*
 * Projekt na Kryptografię (zad 1) - Szyfrowanie symetryczne "Triple DES"
 * Copyright (C) 2026 Igor Wiktorowicz & Viktor Sliednyk
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

package kryptografia;
///
/// @@
public class DES {

    //Podklucze
    private byte[][] subKeys = new byte[16][48];
    ///
    /// Konstruktor ktore laduje haslo do klasy DES dla optymizacji obliczen
    /// @param key Haslo o rozmiarze 64 bitow
    /// @implNote W {@link #subKeys} przechowuja sie klucze poszczegolnych rund
    public DES(byte[] key){
        byte[] keyBits = unpackBits(key);
        byte[] key56 = permute(keyBits,PC1);
        byte[] leftKey = new byte[28];
        byte[] rightKey = new byte[28];

        System.arraycopy(key56, 0, leftKey, 0, 28);
        System.arraycopy(key56, 28, rightKey, 0, 28);
        for(int i = 0; i < 16; i++){
            leftKey = rotateLeft(leftKey,SHIFTS[i]);
            rightKey = rotateLeft(rightKey,SHIFTS[i]);
            byte[] connectedHalfsKey = new byte[56];
            System.arraycopy(leftKey, 0, connectedHalfsKey, 0, 28);
            System.arraycopy(rightKey, 0, connectedHalfsKey, 28, 28);
            subKeys[i]=permute(connectedHalfsKey,PC2);
        }
    }
    //VARIABLES
    // Permutacja poczatkowa (Initial Permutation - IP)
    private static final byte[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    // Permutacja koncowa (Final Permutation - IP^-1)
    private static final byte[] FP = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41,  9, 49, 17, 57, 25
    };

    // Funkcja rozszerzenia E (Expansion) - robi z 32 bitow 48 bitow
    private static final byte[] E = {
            32,  1,  2,  3,  4,  5,
            4,  5,  6,  7,  8,  9,
            8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
    };

    // Permutacja P (wewnatrz funkcji f)
    private static final byte[] P = {
            16,  7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2,  8, 24, 14,
            32, 27,  3,  9,
            19, 13, 30,  6,
            22, 11,  4, 25
    };



    //===========================================================
    //KLUCZE ORAZ JE TABLICE
    //===========================================================

    // Permuted Choice 1 (PC-1) - redukuje klucz z 64 do 56 bitow
    private static final byte[] PC1 = {
            57, 49, 41, 33, 25, 17,  9,
            1, 58, 50, 42, 34, 26, 18,
            10,  2, 59, 51, 43, 35, 27,
            19, 11,  3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14,  6, 61, 53, 45, 37, 29,
            21, 13,  5, 28, 20, 12,  4
    };

    // Permuted Choice 2 (PC-2) - wybiera 48 bitow klucza z 56 bitow
    private static final byte[] PC2 = {
            14, 17, 11, 24,  1,  5,
            3, 28, 15,  6, 21, 10,
            23, 19, 12,  4, 26,  8,
            16,  7, 27, 20, 13,  2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    // Tabela przsuniec (Shift Table) dla generatora kluczy w 16 rundach
    private static final byte[] SHIFTS = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    //===========================================================

    // 8 S-Boxów (Kazdy to tablica 4x16)
    private static final byte[][][] SBOX = {
            {       {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
                    { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
                    { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
                    {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13} },

            {       {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
                    { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
                    { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
                    {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9} },

            {       {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
                    {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
                    {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
                    { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12} },

            {       { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
                    {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
                    {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
                    { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14} },

            {       { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
                    {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
                    { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
                    {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3} },

            {       {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
                    {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
                    { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
                    { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13} },

            {       { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
                    {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
                    { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
                    { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12} },

            {       {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
                    { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
                    { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
                    { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11} }
    };








/// Glowna funkcja do szyfrowania bloku danych
///
/// @param data8ByteBlock Blok o rozmiarze 8 bajtow podawane przez klase spinajaca
/// @return {@code byte[]} zaszyfrowany blok o rozmiarze 8 bajtow
/// @implNote Zaklada sie ze calosc podzialu na bloki oraz wszystkie iteracje zostana podjete w klasie TripleDES
/// Do tej klasy sie podaje czyste bloki o rozmiarze 8 bajtow
/// Gowna zasada tej fynkcji jest dzialanie na bitach zamiast bajtow (Uzywa sie : {@link #unpackBits(byte[])} oraz {@link #packBits(byte[])})
    public byte[] encryptBlock(byte[] data8ByteBlock) {
        byte[] bits = unpackBits(data8ByteBlock);
        //Initial permutation
        bits = permute(bits, IP);

        byte[] L = new byte[32];
        byte[] R = new byte[32];
        System.arraycopy(bits, 0, L, 0, 32);
        System.arraycopy(bits, 32, R, 0, 32);

        for (int i =0; i<16;i++){
           byte[] prevL = L;
           L = R;

           byte[] resultAfterF = functionF(R,subKeys[i]);
           R = XOR(prevL, resultAfterF, 32);
        }

        byte[] finalResult = new byte[64];

        // Tez zamieniamy (przedostatni swap, ostatni w FEISTEL Structure)
        System.arraycopy(R, 0, finalResult, 0, 32);
        System.arraycopy(L, 0, finalResult, 32, 32);
        byte[] result = permute(finalResult, FP);

        return packBits(result);
    }

    /// Funkcja deszyfrujaca blok o rozmiarze 8 bajtow
    /// @param data8ByteBlock Blok o rozmiarze 8 bajtow podawane przez klase spinajaca
    /// @return {@code byte[]} odszyfrowany blok o rozmiarze 8 bajtow
    /// @implNote Zaklada sie ze calosc podzialu na bloki oraz wszystkie iteracje zostana podjete w klasie TripleDES
    /// Do tej klasy sie podaje czyste bloki o rozmiarze 8 bajtow
    /// Gowna zasada tej fynkcji jest dzialanie na bitach zamiast bajtow (Uzywa sie : {@link #unpackBits(byte[])} oraz {@link #packBits(byte[])})
    public byte[] decryptBlock(byte[] data8ByteBlock) {
    byte[] bits = unpackBits(data8ByteBlock);
    bits = permute(bits, IP);
        byte[] L = new byte[32];
        byte[] R = new byte[32];
        System.arraycopy(bits, 0, L, 0, 32);
        System.arraycopy(bits, 32, R, 0, 32);
        for(int i = 15; i>=0 ; i--){
            byte[] prevL = L;
            L = R;
            byte[] resultAfterF = functionF(R,subKeys[i]);
            R = XOR(prevL, resultAfterF, 32);
        }
        byte[] finalResult = new byte[64];
        System.arraycopy(R, 0, finalResult, 0, 32);
        System.arraycopy(L, 0, finalResult, 32, 32);
        byte[] result = permute(finalResult, FP);
        return packBits(result);
    }



    /// Funkcja "Des round function" wewnatrz DES'a
    /// @param rightSide dane o glugosci 32 bitow
    /// @param roundKey klucz danej rundy o dlugosci 48 bitow
    /// @return {@code byte[32]} zwraca dane po SBox'ach czyli w postacio 32 bitow
    /// @implNote Uzywa funkcji XOR : {@link #XOR(byte[], byte[], int)}
    private byte[] functionF(byte[] rightSide, byte[] roundKey){
        byte[] expandedRightSide = permute(rightSide, E);

        byte[] poXOR = XOR(expandedRightSide, roundKey, 48);

        byte[] poSBox = new byte[32];

        for(int i = 0; i<8; i++){
            byte bit1 = poXOR[i*6];
            byte bit2 = poXOR[i*6+1];
            byte bit3 = poXOR[i*6+2];
            byte bit4 = poXOR[i*6+3];
            byte bit5 = poXOR[i*6+4];
            byte bit6 = poXOR[i*6+5];

            int row = (bit1<<1) | bit6;
            int col = (bit2<<3) | (bit3<<2) | (bit4<<1) | bit5;

            int valueZBox = SBOX[i][row][col];

            poSBox[i*4] = (byte) ((valueZBox >> 3) & 1);
            poSBox[i*4+1] = (byte) ((valueZBox >> 2) & 1);
            poSBox[i*4+2] = (byte) ((valueZBox >> 1) & 1);
            poSBox[i*4+3] = (byte) (valueZBox & 1);
        }

        return permute(poSBox, P);


    }















    // Funkcje narzedziowe
    ///
    /// Funkcja do wykonywania operacji XOR na 2 tabelach bajtowych/bitowych
    /// @param entrance1 pierwsza tabela
    /// @param entrance2 druga tabela
    /// @param unifiedLength wspolna dlugosc podanych tabeli
    /// @return byte[]
    private byte[] XOR(byte[] entrance1, byte[] entrance2, int unifiedLength) {
        byte[] result = new byte[unifiedLength];
        for(int i = 0; i < unifiedLength; i++) result[i] = (byte)(entrance1[i] ^ entrance2[i]);
        return result;
    }


    /// Funkcja uzywana do rotacji elementow w kluczach wlewo o zadana liczbe przesuniec
    /// @implNote Uzywana w polaczeniu z konstruktorem {@code DES(String)}
    ///  przy tych kawalkach kodu
    /// {@code leftKey = rotateLeft(leftKey,SHIFTS[...]);
    /// rightKey = rotateLeft(rightKey,SHIFTS[...]);}}
    /// @param bits tabela bitow do przesuniecia
    /// @param howMuchRotation o ile przesuwamy
    /// @return {@code byte[]} wynik z przesunietymi bitami
    ///
    private byte[] rotateLeft(byte[] bits, int howMuchRotation){
        byte[] result = new byte[bits.length];
        for(int i = 0; i< bits.length; i++){
            result[i] = bits[(i+howMuchRotation)%bits.length];
        }
        return result;
    }

    ///
    /// Funkcja do przestawiania bajtow zgodnie z wzorcem
    /// @param entrance tabela zrodlowa
    /// @param layout wzorzec wedlug ktorego sie przestawia
    /// @return byte[]
    private byte[] permute(byte[] entrance, byte[] layout){
        byte[] result = new byte[layout.length];
        for(int i = 0; i < layout.length; i++){
            result[i] = entrance[layout[i]-1];
        }
        return result;
    }

    ///
    /// Funkcja ktora przeksztalca dane z postaci bajtowej do postaci bitowej
    /// @param entrance tabela bajtow
    /// @return byte[]
    private byte[] unpackBits(byte[] entrance){
        byte[] result = new byte[entrance.length*8];
        for(int i = 0; i < entrance.length; i++){
            for(int j = 0; j < 8; j++){
                result[i*8+j] = (byte)((entrance[i]>>(7-j) )& 1);//zawsze bierze tylko najmlodszy bit ,
                // wlasciwie gdzie przesuwamy wartosc bitu z bajtu o danym indeksie
            }
        }
        return result;
    }

    ///
    /// Funkcja ktora przeksztalca dane z postaci bitowej na postac bajtowa
    /// @param entrance tabela bitow
    /// @return byte[]
    private byte[] packBits(byte[] entrance){
        byte[] result = new byte[entrance.length/8];
        for(int i = 0; i < result.length; i++){
            int intByte=0;
            for(int j = 0; j < 8; j++){
                intByte = (intByte<<1) | (entrance[i*8+j]); // Int reprezentuje nasz byte
                // do ktorego pojedynczo wpisujemy wartosci naszych bitow i
                // przesuwamy o jeden po czym kazdy bajt zapisujemy do tablicy wynikowej
            }
            result[i] = (byte)intByte;
        }
        return result;
    }
}
