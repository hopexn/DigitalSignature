#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#define BUFFERSIZE 1000000
/*
    * 加密后的数据格式：
    * 获取文件总长度 doc_len
    * 文件内容格式：
    *   0 ~ doc_len： 经DES加密后文件的密文
    *   doc_len ~ doc_len+256:  经RSA加密后的DES密文
    *   doc_len+256 ~ doc_len+512:  前面两部分数据的签名
*/

int main(int argc, char **argv) {
    DES_cblock key;
    DES_key_schedule schedule;
    char des_pwd[128] = "qwertyui";
    char des_pwd_out[128];
    unsigned char sign_value[512];
    unsigned char buf_in[BUFFERSIZE], buf_out[BUFFERSIZE];
    long doc_len;
    long len, ret;
    unsigned int sign_len;
    DES_cblock ivec;
    RSA* rsa_pub_key_a;
    RSA* rsa_pvt_key_a;
    RSA* rsa_pub_key_b;
    EVP_PKEY *evpKey=NULL;      //EVP KEY结构体变量
    SHA_CTX shactx;
    EVP_MD_CTX mdctx;

    FILE *fp_doc = fopen("./documents/财务报表.doc", "rb");
    FILE *fp_pub_key_a = fopen("./rsa_public_key_a.pem", "r");
    FILE *fp_pub_key_b = fopen("./fromB/rsa_public_key_b.pem", "r");
    FILE *fp_pvt_key_a = fopen("./rsa_private_key_a.pem", "r");
    FILE *fp_doc_crypted = fopen("./toB/财务报表_加密.doc", "wb");

    srand(time(NULL));
    OpenSSL_add_all_algorithms();

    rsa_pub_key_a = RSA_new();
    rsa_pvt_key_a = RSA_new();
    rsa_pub_key_b = RSA_new();
    evpKey = EVP_PKEY_new();//新建一个EVP_PKEY变量



    if (fp_pub_key_a == NULL) {
        printf("ERROR: 无法打开A的公钥文件！");
        exit(0);
    }
    if (fp_pvt_key_a == NULL) {
        printf("ERROR: 无法打开A的私钥文件！");
        exit(0);
    }
    if (fp_pub_key_b == NULL) {
        printf("ERROR: 无法打开B的公钥文件！");
        exit(0);
    }
    if (fp_doc == NULL) {
        printf("ERROR: 无法打开文档'财务报表.doc'！");
        exit(0);
    }
    if (fp_doc_crypted == NULL) {
        printf("ERROR: 无法打开'财务报表_加密.doc'！");
        exit(0);
    }

    PEM_read_RSA_PUBKEY(fp_pub_key_a, &rsa_pub_key_a, 0, 0);
    PEM_read_RSAPrivateKey(fp_pvt_key_a, &rsa_pvt_key_a, 0, 0);
    PEM_read_RSA_PUBKEY(fp_pub_key_b, &rsa_pub_key_b, 0, 0);

    if(evpKey == NULL)
    {
        printf("EVP_PKEY_new err\n");
        exit(0);
    }
    if(EVP_PKEY_set1_RSA(evpKey,rsa_pvt_key_a) != 1)  //保存RSA结构体到EVP_PKEY结构体
    {
        printf("EVP_PKEY_set1_RSA err\n");
        exit(0);
    }

    fseek(fp_doc,0,SEEK_END); //定位到文件末
    doc_len = ftell(fp_doc); //文件长度
    rewind(fp_doc);

    //生成密钥
    DES_string_to_key(des_pwd, &key);

    //转换成schedule
    DES_set_key_checked(&key, &schedule);
    //使用DES加密文件
    fread(buf_in, sizeof(char), doc_len, fp_doc);
    DES_ncbc_encrypt(buf_in, buf_out, doc_len, &schedule, &ivec, DES_ENCRYPT);

    //使用RSA公钥加密DES密钥，保存在toB/des_pwd.txt
    ret = RSA_public_encrypt(strlen(des_pwd), (const unsigned char*)des_pwd, (unsigned char*)des_pwd_out, rsa_pub_key_b, RSA_PKCS1_PADDING);
    if(ret < 0){
        printf("DES密码的公钥加密失败！");
        exit(0);
    }
    memcpy(buf_out+doc_len, des_pwd_out, ret);
    doc_len+=ret;
    printf("%d\n", EVP_PKEY_size(evpKey));
    //初始化签名函数
    EVP_MD_CTX_init(&mdctx);
    if(!EVP_SignInit_ex(&mdctx, EVP_md5(), NULL))//签名初始化，设置摘要算法，本例为MD5
    {
        printf("err1\n");
        exit(0);
    }
    if(!EVP_SignUpdate(&mdctx, buf_out, doc_len))//计算签名（摘要）Update
    {
        printf("err2\n");
        exit(0);
    }

    if(!EVP_SignFinal(&mdctx,sign_value,&sign_len,evpKey))  //签名输出
    {
        printf("%u\n", sign_len);
        printf("err3\n");
        exit(0);
    }
    memcpy(buf_out+doc_len, sign_value, sign_len);
    doc_len+=sign_len;
    printf("Success!\n");
    //写入数据
    fwrite(buf_out, sizeof(char), doc_len, fp_doc_crypted);

    //释放资源
    RSA_free(rsa_pub_key_a);
    RSA_free(rsa_pub_key_b);
    RSA_free(rsa_pvt_key_a);
    // //关闭文件
    fclose(fp_doc);
    fclose(fp_doc_crypted);
    fclose(fp_pvt_key_a);
    fclose(fp_pub_key_b);
    fclose(fp_pub_key_b);
    return 0;
}
