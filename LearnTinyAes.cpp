// LearnTinyAes.cpp : Defines the entry point for the application.
//


#include <vector>

#include "LearnTinyAes.h"
#include "aes.hpp"

#define MAX_FILESTORE_SIZE_IN_CHARS 4000 /* MULTIPLE OF 16 */

using namespace std;


uint8_t key[] = {
    0x01,0x02,0x03,0x04,
    0x04,0x03,0x02,0x01,
    0x01,0x02,0x03,0x04,
    0x04,0x03,0x02,0x01
};

uint8_t iv[] = {
    0x01,0x02,0x03,0x04,
    0x04,0x03,0x02,0x01,
    0x01,0x02,0x03,0x04,
    0x07,0x07,0x07,0x07
};

int main()
{
    cout << "Learning TinyAes" << endl;
    string plainText = "Mary had a little lamb";

    // ############################################################ //
    // ##############          ENCRYPTION        ################## //
    // ############################################################ //

    struct AES_ctx ctx;
    uint8_t buffer[MAX_FILESTORE_SIZE_IN_CHARS] = { 0x0};
    int paddingLength = plainText.size() % 16;

    // Padding using PCKS method: http://www.crypto-it.net/eng/theory/padding.html
    if (paddingLength != 0)
    {
        for (int i = 0; i < paddingLength; i++)
        {
            plainText += paddingLength;
        }
    }

    vector<uint8_t> myVector(plainText.begin(), plainText.end());

    for (int i = 0; i < plainText.size(); i++)
    {
        uint8_t c = myVector[i];
        buffer[i] = c;
    }

    AES_init_ctx_iv(&ctx, key, iv);

    AES_CBC_encrypt_buffer(&ctx, buffer, MAX_FILESTORE_SIZE_IN_CHARS);

    // ############################################################ //
    // ##############          DECRYPTION        ################## //
    // ############################################################ //

    struct AES_ctx dctx;
    uint8_t dbuffer[MAX_FILESTORE_SIZE_IN_CHARS] = { 0x0 };

    // copy encrypted data to decryption buffer
    for (int i = 0; i < MAX_FILESTORE_SIZE_IN_CHARS; i++)
    {
        if (buffer[i] == '\0')
            break;

        dbuffer[i] = buffer[i];
    }

    AES_init_ctx_iv(&dctx, key, iv);
    AES_CBC_decrypt_buffer(&dctx, dbuffer, MAX_FILESTORE_SIZE_IN_CHARS);

    // ############################################################ //
    // ##########  REMOVING PADDING AFTER DECRYPTION    ########### //
    // ############################################################ //

    uint8_t paddingChar = 0x0;
    int dataEndPos = -1;

    for (int i = 1; i < MAX_FILESTORE_SIZE_IN_CHARS; i++)
    {
        if (dbuffer[i] == 0x0)
        {
            paddingChar = dbuffer[i - 1]; /* loop must start from 1 to prevent -1 indexing */
            dataEndPos = i - 1;
            break;
        }
    }

    int paddingCount = 0;

    for (int i = dataEndPos; i > 0; i--)
    {
        if (dbuffer[i] == paddingChar)
            paddingCount++;
    }

    bool hasPadding = (paddingCount == (int)paddingChar);

    string decryptedText = "";

    if (hasPadding)
    {
        for (int i = 0; i < dataEndPos - paddingCount + 1; i++)
            decryptedText += (char)dbuffer[i];
    }

    cout << "Decrypted text " << decryptedText << endl;

	return 0;
}
