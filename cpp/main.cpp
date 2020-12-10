#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <assert.h>

std::string privateKey ="-----BEGIN RSA PRIVATE KEY-----\n"
                        "MIICXQIBAAKBgQDlLm5+Kosybacfp8hzjn1fl2wT7Au2lm5SEtz6r+/wwSfq5KfY\n"
                        "H8q1AO/C92IwEpplNbrqYmOXQu6P07mg0lQOCvE5sdtmAvD2ex3wCef8lWmgdh5q\n"
                        "Uo4OMcmoSz3IAp/7/FnMag1IelSfdronPBDxazp6NUmQZITsYK6CsEl/ewIDAQAB\n"
                        "AoGBAJkMdvF+i9Kzc6YqMC0rfQJ3Zs+vFOtsbmQVAMnQ8JWBCJ1O8d/c60wRQgyb\n"
                        "lFCyO7VXOmoIJqX/Jr2aER8bFtG+Yxy6jsMu3ynwMwbhcVmCWCmZoWuE5pZdEJk6\n"
                        "lOdOay7TkE45X/Wc7K9iZs2uuB7sylIvK/HVxxit6FGePa4RAkEA9e+VoAbxBv78\n"
                        "HyxRcStW+Kc3lmE4zYBGAb2IYx48UEN34nP5rI8Tusqsy7CZ3rvSMi1CpVlj2eQK\n"
                        "FU8FzVFyjwJBAO6PU9q7il8NtecdvYBkDErlCawSeCdk9s79helT0Mrg9cWaVWFO\n"
                        "n0UxgT55MPXWGdMRXUUOCNnMilaw/p7dKlUCQDpjGeu3GivmB2dDN0ad2nUIBftu\n"
                        "s3SeWoB5RdL6T6liiyi5DfJ4uV9kVKe7Epy9jIabFjJ5SWpmaDps21zGVGMCQQCB\n"
                        "HvK0IW3zpOgf/+jh5UUCBJYHnLeMGwm7X11rvQH1zW05Vx9/W565ROI/fjkR1qCD\n"
                        "rZJeHgqMWDlIUuR9+BdBAkAI8+JWgWLdWceXX9Puu4KNmGukx4GZw2n53vMKp0Fu\n"
                        "puQxMonRWTN+kA76cq8QIj8xuEBkdxy1NFRMEkGu675m\n"
                        "-----END RSA PRIVATE KEY-----";

std::string publicKey ="-----BEGIN PUBLIC KEY-----\n"
                       "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlLm5+Kosybacfp8hzjn1fl2wT\n"
                       "7Au2lm5SEtz6r+/wwSfq5KfYH8q1AO/C92IwEpplNbrqYmOXQu6P07mg0lQOCvE5\n"
                       "sdtmAvD2ex3wCef8lWmgdh5qUo4OMcmoSz3IAp/7/FnMag1IelSfdronPBDxazp6\n"
                       "NUmQZITsYK6CsEl/ewIDAQAB\n"
                       "-----END PUBLIC KEY-----";

RSA* createPrivateRSA(std::string key) {
    RSA *rsa = NULL;
    const char* c_string = key.c_str();
    BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
    if (keybio==NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    return rsa;
}

RSA* createPublicRSA(std::string key) {
    RSA *rsa = NULL;
    BIO *keybio;
    const char* c_string = key.c_str();
    keybio = BIO_new_mem_buf((void*)c_string, -1);
    if (keybio==NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    return rsa;
}

bool RSASign( RSA* rsa,
              const unsigned char* Msg,
              size_t MsgLen,
              unsigned char** EncMsg,
              size_t* MsgLenEnc) {
    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY* priKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);
    if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
        return false;
    }
    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
        return false;
    }
    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
        return false;
    }
    EVP_MD_CTX_free(m_RSASignCtx);
    return true;
}

bool RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         bool* Authentic) {
    *Authentic = false;
    EVP_PKEY* pubKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

    if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
        return false;
    }
    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
    if (AuthStatus==1) {
        *Authentic = true;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return true;
    } else if(AuthStatus==0){
        *Authentic = false;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return true;
    } else{
        *Authentic = false;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return false;
    }
}

void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());

    // 控制 base64 输出字符串不换行
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *base64Text=(*bufferPtr).data;
}

size_t calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;
    return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());

    // 控制 base64 输出字符串不换行
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}

char* signMessage(std::string privateKey, std::string plainText) {
    RSA* privateRSA = createPrivateRSA(privateKey);
    unsigned char* encMessage;
    char* base64Text;
    size_t encMessageLength;
    RSASign(privateRSA, (unsigned char*) plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
    Base64Encode(encMessage, encMessageLength, &base64Text);
    free(encMessage);
    return base64Text;
}

bool verifySignature(std::string publicKey, std::string plainText, char* signatureBase64) {
    RSA* publicRSA = createPublicRSA(publicKey);
    unsigned char* encMessage;
    size_t encMessageLength;
    bool authentic;
    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
    bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
    return result & authentic;
}

int main() {
    std::string plainText = "Hello, sha256 with rsa!";
    char* signature = signMessage(privateKey, plainText);
    std::cout << signature << std::endl;
    bool authentic = verifySignature(publicKey, "Hello, sha256 with rsa!", signature);
    if ( authentic ) {
        std::cout << "Authentic" << std::endl;
    } else {
        std::cout << "Not Authentic" << std::endl;
    }
}