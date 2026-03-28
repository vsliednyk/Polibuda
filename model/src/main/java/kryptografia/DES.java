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

public class DES {














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
                result[i*8+j] = (byte)((entrance[i]>>(j-1) )& 1);//zawsze bierze tylko najmlodszy bit ,
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
        for(int i = 0; i < entrance.length; i++){
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
