#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define PASSWORD_LENGTH 36 // パスワードの長さ

// 利用可能な文字セットを定義
const char lowercase_chars[] = "abcdefghijklmnopqrstuvwxyz";
const char uppercase_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char digit_chars[]     = "0123456789";
const char special_chars[]   = "!@#$%^&*()_-+={}[]:;<>,.?/~`|";

// Function to generate a password of a specified length
void generatePassword(char* password_buffer, int length) {
    // 全ての利用可能な文字を格納するプール
    char available_chars[256]; // 十分なサイズを確保
    int available_count = 0;

    // 各文字セットをプールに追加
    strcat(available_chars, lowercase_chars);
    strcat(available_chars, uppercase_chars);
    strcat(available_chars, digit_chars);
    strcat(available_chars, special_chars);
    available_count = strlen(available_chars);

    // パスワードの長さが利用可能なユニーク文字の総数を超えていないかチェック
    if (length > available_count) {
        fprintf(stderr, "Error: Password length (%d) exceeds the number of unique available characters (%d).\n", length, available_count);
        password_buffer[0] = '\0'; // 空の文字列をセットして終了
        return;
    }

    int i;
    for (i = 0; i < length; i++) {
        // 残っている文字の中からランダムに一つ選ぶ
        int random_index = rand() % available_count;
        password_buffer[i] = available_chars[random_index];

        // 選んだ文字をプールから「削除」する（末尾の文字と入れ替えて、カウントを減らす）
        available_chars[random_index] = available_chars[available_count - 1];
        available_count--;
    }
    password_buffer[length] = '\0'; // ヌル終端
}

int main() {
    srand(time(NULL)); // 乱数シードの初期化

    char password[PASSWORD_LENGTH + 1]; // パスワードバッファを定義 (+1 はヌル終端のため)
    generatePassword(password, PASSWORD_LENGTH);

    if (strlen(password) > 0) { // エラーで空文字列でない場合
        printf("Generated Password: %s\n", password);
    }

    return 0;
}
