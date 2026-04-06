
#include <iostream>
#include <string>
#include <vector>
#include <cctype>

using namespace std;

// Hàm tạo ma trận 5x5 từ Key
void generateMatrix(string key, char matrix[5][5]) {
    bool used[26] = {false};
    used['J' - 'A'] = true; // Gộp J vào I
    
    int r = 0, c = 0;
    
    // Đưa key vào ma trận
    for (char ch : key) {
        if (isalpha(ch)) {
            ch = toupper(ch);
            if (ch == 'J') ch = 'I';
            if (!used[ch - 'A']) {
                matrix[r][c++] = ch;
                used[ch - 'A'] = true;
                if (c == 5) { c = 0; r++; }
            }
        }
    }
    
    // Điền các chữ cái còn lại trong bảng chữ cái
    for (char ch = 'A'; ch <= 'Z'; ch++) {
        if (!used[ch - 'A']) {
            matrix[r][c++] = ch;
            if (c == 5) { c = 0; r++; }
        }
    }
}

// Hàm chuẩn bị bản rõ (Plaintext)
string prepareText(string text) {
    string cleaned = "";
    for (char ch : text) {
        if (isalpha(ch)) {
            ch = toupper(ch);
            if (ch == 'J') ch = 'I';
            cleaned += ch;
        }
    }
    
    string prepared = "";
    for (size_t i = 0; i < cleaned.length(); i += 2) {
        prepared += cleaned[i];
        if (i + 1 < cleaned.length()) {
            if (cleaned[i] == cleaned[i+1]) {
                prepared += 'X'; // Chèn X nếu 2 ký tự trong cặp giống nhau
                i--; // Lùi lại để xử lý ký tự thứ 2 trong cặp tiếp theo
            } else {
                prepared += cleaned[i+1];
            }
        }
    }
    
    // Nếu độ dài lẻ, thêm X vào cuối
    if (prepared.length() % 2 != 0) {
        prepared += 'X';
    }
    return prepared;
}

// Hàm tìm vị trí của một ký tự trong ma trận
void findPosition(char matrix[5][5], char ch, int &row, int &col) {
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            if (matrix[i][j] == ch) {
                row = i;
                col = j;
                return;
            }
        }
    }
}

// Hàm mã hóa
string encrypt(string preparedText, char matrix[5][5]) {
    string cipherText = "";
    for (size_t i = 0; i < preparedText.length(); i += 2) {
        char a = preparedText[i];
        char b = preparedText[i+1];
        int r1, c1, r2, c2;
        
        findPosition(matrix, a, r1, c1);
        findPosition(matrix, b, r2, c2);
        
        if (r1 == r2) {
            // Cùng hàng: dịch sang phải 1 cột
            cipherText += matrix[r1][(c1 + 1) % 5];
            cipherText += matrix[r2][(c2 + 1) % 5];
        } else if (c1 == c2) {
            // Cùng cột: dịch xuống dưới 1 hàng
            cipherText += matrix[(r1 + 1) % 5][c1];
            cipherText += matrix[(r2 + 1) % 5][c2];
        } else {
            // Hình chữ nhật: giữ nguyên hàng, đổi chéo cột
            cipherText += matrix[r1][c2];
            cipherText += matrix[r2][c1];
        }
    }
    return cipherText;
}

// Hàm in ma trận
void printMatrix(char matrix[5][5]) {
    cout << "Ma tran Playfair (5x5) " << endl;
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            cout << matrix[i][j] << " ";
        }
        cout << endl;
    }
}

int main() {
    string key = "MONARCHY";
    string plaintext = "DO YOU LIKE TO STUDY A CRYPTOGRAPHY COURSE";
    char matrix[5][5];

    cout << "Key: " << key << endl;
    cout << "Thong tin gui di: " << plaintext << "\n\n";

    generateMatrix(key, matrix);
    printMatrix(matrix);

    string preparedText = prepareText(plaintext);
    cout << "\nVan ban sau khi chuan bi: " << endl;
    for (size_t i = 0; i < preparedText.length(); i += 2) {
        cout << preparedText[i] << preparedText[i+1] << " ";
    }
    cout << "\n";

    string ciphertext = encrypt(preparedText, matrix);
    
    cout << "\n=> BAN MA: " << endl;
    for (size_t i = 0; i < ciphertext.length(); i += 2) {
        cout << ciphertext[i] << ciphertext[i+1] << " ";
    }
    cout << "\n";

    return 0;
}