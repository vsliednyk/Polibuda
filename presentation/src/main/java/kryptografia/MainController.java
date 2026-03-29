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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

package kryptografia;

import javafx.fxml.FXML;
import javafx.scene.control.*;
///
/// Glowna klasa obslugujaca UI
///
public class MainController {
///
/// Kontrolki
///
/// Klucze
    @FXML private TextField key1Field;
    @FXML private TextField key2Field;
    @FXML private TextField key3Field;
    @FXML private Button generateKeysBtn;
/// Pola kluczy
    @FXML private TextField loadKeyPathField;
    @FXML private Button loadKeyBtn;
    @FXML private TextField saveKeyPathField;
    @FXML private Button saveKeyBtn;
/// Pola po lewej stronei (tekst)
    @FXML private TextField openPlainPathField;
    @FXML private Button openPlainBtn;
    @FXML private TextArea plainTextArea;
    @FXML private TextField savePlainPathField;
    @FXML private Button savePlainBtn;
    @FXML private Label plainStatusTitle;
///  Przyciski
    @FXML private Button encryptBtn;
    @FXML private Button decryptBtn;
    @FXML private ToggleGroup modeToggleGroup;
    @FXML private RadioButton fileModeRadio;
    @FXML private RadioButton windowModeRadio;
/// Pola po prawej stronie (Szyfr)
    @FXML private TextField openCipherPathField;
    @FXML private Button openCipherBtn;
    @FXML private TextArea cipherTextArea;
    @FXML private TextField saveCipherPathField;
    @FXML private Button saveCipherBtn;
    @FXML private Label cipherStatusTitle;



///
/// Funkcja inicjujaca , przypisujaca eventy
    @FXML
    public void initialize() {
        generateKeysBtn.setOnAction(event -> handleGenerateKeys());
        encryptBtn.setOnAction(event -> handleEncrypt());
        decryptBtn.setOnAction(event -> handleDecrypt());

        modeToggleGroup.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            boolean isFileMode = fileModeRadio.isSelected();
            plainTextArea.setDisable(isFileMode);
            cipherTextArea.setDisable(isFileMode);
            openPlainPathField.setDisable(!isFileMode);
            openCipherPathField.setDisable(!isFileMode);
            openPlainBtn.setDisable(!isFileMode);
            openCipherBtn.setDisable(!isFileMode);
        });

        plainTextArea.setDisable(true);
        cipherTextArea.setDisable(true);
        plainStatusTitle.setText("Test plain");
        cipherStatusTitle.setText("Test cipher");

    }

    private void handleGenerateKeys() {
        System.out.println("Kliknięto: Generuj klucze");
        // TODO: Wywołanie generatora z modułu model i wpisanie wyników do key1Field, key2Field, key3Field
    }

    private void handleEncrypt() {
        System.out.println("Kliknięto: Szyfruj ->");
        if (fileModeRadio.isSelected()) {
            System.out.println("Wybrano tryb PLIK. Szyfruję plik...");
        } else {
            System.out.println("Wybrano tryb OKNO. Szyfruję tekst...");
        }
    }

    private void handleDecrypt() {
        System.out.println("Kliknięto: <- Deszyfruj");
        // TODO: Logika deszyfrowania
    }


}