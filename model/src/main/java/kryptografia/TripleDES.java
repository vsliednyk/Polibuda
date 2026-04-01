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

/// Klasa <strong>TripleDES<strong/> wlasciwie uzywana w <MainController>
/// @implNote Klasa spinajaca
public class TripleDES {

    private DES des1;
    private DES des2;
    private DES des3;
///
/// Konstruktor gdzie ladujemy wszystkie klucze (1.,2.,3.)
    public TripleDES(byte[] key1, byte[] key2, byte[] key3) {
        this.des1 = new DES(key1);
        this.des2 =  new DES(key2);
        this.des3 = new DES(key3);
    }
///
/// Funkcja do zaszyfrowania danych podawanych jako bajtow
/// @param data dowolne dane podane w bajtach
/// @return {@code byte[]} bajty po zaszyfrowaniu
/// @see DES#encryptBlock(byte[])
/// @see DES#decryptBlock(byte[])
/// @implNote Funkcja uzywa funkcji {@link DataConverter#addPKCS7DESPadding(byte[])} ktora dopasowuje dane o nieprawidlowym rzmiarze do rozmiaru o 8 bajtow
    public byte[] encrypt(byte[] data){
        byte[] expandedData = DataConverter.addPKCS7DESPadding(data);
        byte[] resultData = new byte[expandedData.length];
        for(int i = 0; i< expandedData.length; i+=8){
            byte[] block8Bytes =  new byte[8];
            System.arraycopy(expandedData, i, block8Bytes, 0, 8);
            byte[] step1Data = des1.encryptBlock(block8Bytes);
            byte[] step2Data = des2.decryptBlock(step1Data);
            byte[] finalData = des3.encryptBlock(step2Data);
            System.arraycopy(finalData, 0, resultData, i, 8);
        }
        return resultData;
    }
    ///
    /// Funkcja do deszyfrowania danych podawanych jako bajtow
    /// @param data dowolne dane podane w bajtach
    /// @return {@code byte[]} bajty po deszyfrowaniu
    /// @see DES#encryptBlock(byte[])
    /// @see DES#decryptBlock
    /// @implNote Funkcja uzywa funkcji {@link DataConverter#removePKCS7DESPadding(byte[])} ktora przywraca stan poczatkowy
    public byte[] decrypt(byte[] data){
        byte[] resultData = new byte[data.length];
        for(int i = 0; i< data.length; i+=8){
            byte[] block8Bytes =  new byte[8];
            System.arraycopy(data, i, block8Bytes, 0, 8);
            byte[] step1Data = des3.decryptBlock(block8Bytes);
            byte[] step2Data = des2.encryptBlock(step1Data);
            byte[] finalData = des1.decryptBlock(step2Data);
            System.arraycopy(finalData, 0, resultData, i, 8);
        }
        return DataConverter.removePKCS7DESPadding(resultData);
    }
}
