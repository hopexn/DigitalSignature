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

int main(int argc, char **argv) {
    DES_cblock key;
    DES_key_schedule schedule;
    char des_pwd_out[256];
    char des_pwd[256];
    unsigned char sign_value[512];
    unsigned char buf_in[BUFFERSIZE], buf_out[BUFFERSIZE];
    long doc_len;
    long len, ret;
    unsigned int sign_len;
    DES_cblock ivec;
    RSA* rsa_pub_key_b;
    RSA* rsa_pvt_key_b;
    RSA* rsa_pub_key_a;
    EVP_PKEY *evpKey=NULL;      //EVP KEY结构体变量
    SHA_CTX shactx;
    EVP_MD_CTX mdctx;

    FILE *fp_doc_crypted = fopen("./fromA/财务报表_加密.doc", "rb");
    FILE *fp_doc = fopen("./财务报表.doc", "wb");
    FILE *fp_pub_key_b = fopen("./rsa_public_key_b.pem", "r");
    FILE *fp_pvt_key_b = fopen("./rsa_private_key_b.pem", "r");
    FILE *fp_pub_key_a = fopen("./fromA/rsa_public_key_a.pem", "r");

    srand(time(NULL));
    OpenSSL_add_all_algorithms();

    //初始化秘钥对象
    rsa_pub_key_b = RSA_new();
    rsa_pvt_key_b = RSA_new();
    rsa_pub_key_a = RSA_new();
    evpKey = EVP_PKEY_new();//新建一个EVP_PKEY变量

    if (fp_pub_key_b == NULL) {
        printf("ERROR: 无法打开B的公钥文件！");
        exit(0);
    }
    if (fp_pvt_key_b == NULL) {
        printf("ERROR: 无法打开B的私钥文件！");
        exit(0);
    }
    if (fp_pub_key_a == NULL) {
        printf("ERROR: 无法打开A的公钥文件！");
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

    //生成密钥对象
    PEM_read_RSA_PUBKEY(fp_pub_key_a, &rsa_pub_key_a, 0, 0);
    PEM_read_RSAPrivateKey(fp_pvt_key_b, &rsa_pvt_key_b, 0, 0);
    PEM_read_RSA_PUBKEY(fp_pub_key_b, &rsa_pub_key_b, 0, 0);


    if(evpKey == NULL)
    {
        printf("EVP_PKEY_new err\n");
        exit(0);
    }
    if(EVP_PKEY_set1_RSA(evpKey,rsa_pub_key_a) != 1)  //保存RSA结构体到EVP_PKEY结构体
    {
        printf("EVP_PKEY_set1_RSA err\n");
        exit(0);
    }

    /*
    * 获取文件总长度 doc_len
    * 文件内容格式：
    *   0 ~ doc_len： 经DES加密后文件的密文
    *   doc_len ~ doc_len+256:  经RSA加密后的DES密文
    *   doc_len+256 ~ doc_len+512:  前面两部分数据的签名
    */
    fseek(fp_doc_crypted,0,SEEK_END); //定位到文件末
    doc_len = ftell(fp_doc_crypted); //文件长度
    fseek(fp_doc_crypted, doc_len-512, SEEK_SET);  //文件指针移动到doc_len-512
    fread(des_pwd_out, sizeof(char), 256, fp_doc_crypted);  //获取经RSA加密后的DES密玥
    fread(sign_value, sizeof(char), 256, fp_doc_crypted);   //获取数字签名
    rewind(fp_doc_crypted);

    //使用RSA私钥加密DES密钥，保存
    ret = RSA_private_decrypt(256, (const unsigned char*)des_pwd_out, (unsigned char*)des_pwd, rsa_pvt_key_b, RSA_PKCS1_PADDING);
    if(ret < 0){
        printf("DES密码的私钥解密失败！");
        exit(0);
    }
    printf("DES key： %s\n", des_pwd);

    //生成密钥
    DES_string_to_key(des_pwd, &key);
    //转换成schedule
    DES_set_key_checked(&key, &schedule);
    //使用DES解文件
    fread(buf_in, sizeof(char), doc_len-256, fp_doc_crypted);
    DES_ncbc_encrypt(buf_in, buf_out, doc_len-512, &schedule, &ivec, DES_DECRYPT);

    //初始化验证函数
    EVP_MD_CTX_init(&mdctx);
    if(!EVP_VerifyInit_ex(&mdctx, EVP_md5(), NULL))//验证初始化，设置摘要算法，本例为MD5
    {
        printf("err1\n");
        exit(0);
    }
    if(!EVP_VerifyUpdate(&mdctx, buf_in, doc_len-256))//计算（摘要）Update
    {
        printf("err2\n");
        exit(0);
    }

    sign_len = 256;  //签名长度为256
    ret = EVP_VerifyFinal(&mdctx,sign_value, sign_len, evpKey);  //验证开始
    /*返回值1表示通过验证， 0表示未通过， 其他值则为验证错误*/
    if(ret == 1){
        printf("通过签名验证！\n");
    }else if(ret == 0){
        printf("未通过签名验证！\n");
    }else{
        printf("签名验证过程错误！Code:%ld\n", ret);
    }

    //保存解密后的文件
    fwrite(buf_out, sizeof(char), doc_len-512, fp_doc);

    //释放资源
    RSA_free(rsa_pub_key_a);
    RSA_free(rsa_pub_key_b);
    RSA_free(rsa_pvt_key_b);
    //关闭文件
    fclose(fp_doc);
    fclose(fp_doc_crypted);
    fclose(fp_pvt_key_b);
    fclose(fp_pub_key_b);
    fclose(fp_pub_key_a);
    return 0;
}
