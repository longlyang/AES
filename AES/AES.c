#define _CRT_SECURE_NO_WARNINGS//VS 宏，抑制使用不安全函数报错的
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>

typedef uint8_t byte;//定义字节类型
typedef byte(word)[4];//定义字类型（4个字节）
typedef word(state)[4];//定义状态矩阵类型

//读取完密钥文件就设置这三个全局变量
word keys[4 * 15] = { 0 };//根据密钥生成的扩展密钥
uint8_t Nr = 10;//轮数
uint8_t Nk = 4;//密钥‘字’数

const char* AES_MODE[] = { "ECB","CBC","CFB","OFB" };
char* plainfile = NULL;
char* keyfile = NULL;
char* vifile = NULL;
char* mode = NULL;
char* cipherfile = NULL;

byte* plaintext = NULL;
byte* keytext = NULL;
byte* vitext = NULL;
byte* ciphertext = NULL;

uint64_t plaintextlength = 0;
uint64_t vitextlegnth = 0;
uint64_t keytextlength = 0;
uint64_t ciphertextlength = 0;

//S盒
const uint8_t sbox[256] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

//逆S盒
const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

//Rcon
const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

void print_usage() {
    /*
        参数输入错误提示，并退程序
    */
    printf("\n非法输入,支持的参数有以下：\n-p plainfile 指定明文文件的位置和名称\n-k keyfile  指定密钥文件的位置和名称\n-v vifile  指定初始化向量文件的位置和名称\n-m mode  指定加密的操作模式(ECB,CBC,CFB,OFB)\n-c cipherfile 指定密文文件的位置和名称。\n");
    exit(-1);
}

bool readfile2memory(const char* filename, byte** memory, uint64_t* memorylength) {
	/*
	读取文件到内存，同时把字符“4e” 转成一个字节0x4e
	*/
	FILE* fp = NULL;
	fp = fopen(filename, "r");
	if (fp == NULL) {
		return false;
	}
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (size % 2 != 0) {
		printf("%s:文件字节数不为偶数！\n", filename);
		fclose(fp);
		return false;
	}
	byte* tmp = NULL;
	tmp = malloc(size);
	memset(tmp, 0, size);

	fread(tmp, size, 1, fp);
	if (ferror(fp)) {
		printf("读取%s出错了！\n", filename);
		fclose(fp);
		return false;
	}
	else {
		fclose(fp);
	}

	*memory = malloc(size / 2);
	memset(*memory, 0, size / 2);
	*memorylength = size / 2;

	byte parsewalker[3] = { 0 };
	printf("readfile2memory debug info:");
	for (int i = 0; i < size; i += 2) {
		parsewalker[0] = tmp[i];
		parsewalker[1] = tmp[i + 1];
		(*memory)[i / 2] = strtol(parsewalker, 0, 16);
		printf("%c", (*memory)[i / 2]);
	}
	printf("\n");

	free(tmp);

	return true;
}

void print_help(char* bufname, byte* buf, uint8_t bytes) {
	/*
	打印调试信息
	*/
	printf("%s信息:\n", bufname);
	/*for (int i = 0; i < bytes; i++) {
		printf("%c", buf[i]);
	}*/
	//printf("\n");
	for (int i = 0; i < bytes; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n\n");
	/*for (int i = 0; i < bytes; i++) {
		for (int j = 7; j >= 0; j--) {
			if (buf[i] & 1 << j) {
				printf("1");
			}
			else {
				printf("0");
			}
		}
		printf("\n");
	}
	printf("\n\n");*/
}

//该程序实现时参考了一下文档
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
// 下列参考页数简写为 P加页码，比如某个代码参考了上述pdf文档的第19页，则会写ref. P19


void RotWord(word* temp) {
	//处理拓展密钥时的函数，循环左移一个字节 ref. P19
	byte backup = temp[0][0];
	(*(uint32_t*)temp) >>= 8; //小端机器注意了
	temp[0][3] = backup;
}

void SubWord(word* temp) {
	//处理拓展密钥时的函数，s盒查找替换 ref. P19
	temp[0][0] = sbox[temp[0][0]];
	temp[0][1] = sbox[temp[0][1]];
	temp[0][2] = sbox[temp[0][2]];
	temp[0][3] = sbox[temp[0][3]];
}

void KeyExpansion(byte*key,word*w,uint8_t Nk) {
	//密钥拓展成轮密钥序列 ref. P20
	assert(key != NULL && w != NULL && (Nk == 4 || Nk == 6 || Nk == 8));
	uint8_t Nr = (Nk == 6 ? 12 : (Nk == 4 ? 10 : 14));
	word temp = { 0 };
	memcpy(w, key, 4 * Nk);
	uint8_t i = Nk;
	while (i < 4*(Nr + 1)) {
		memcpy(&temp, w + i - 1, 4);
		if (i % Nk == 0) {
			RotWord(&temp);
			SubWord(&temp);
			word RC = { Rcon[i / Nk],0x00,0x00,0x00 };
			*(uint32_t*)temp = (*(uint32_t*)temp) ^ (*(uint32_t*)RC);
		}
		else if (Nk > 6 && i % Nk == 4) {//Nk==8时情况不一样，请注意
			SubWord(&temp);
		}
		*(uint32_t*)(w + i) = *(uint32_t*)(w + i - Nk) ^ (*(uint32_t*)temp);
		i = i + 1;
	}
}

void SubBytes(byte* bs) {
	//AES 关键步骤函数，查找S盒替换 ref. P15
	for (uint8_t i = 0; i < 16; i++) {
		bs[i] = sbox[bs[i]];
	}
}

void InvSubBytes(byte* bs) {
	//AES 解密关键步骤函数，查找逆S盒替换  ref. P22
	for (uint8_t i = 0; i < 16; i++) {
		bs[i] = rsbox[bs[i]];
	}
}

void ShiftRows(state*s) {
	//AES 加密关键步骤函数，左移，  ref. P17 
	byte backup1 = s[0][1][0];
	(*(uint32_t*)((*s) + 1)) >>= 8;//注意小端机器，后续不再提及
	s[0][1][3] = backup1;

	uint16_t backup2 = (*(uint16_t*)((*s) + 2));
	(*(uint16_t*)((*s) + 2)) = (*(uint16_t*)(*((*s) + 2) + 2));
	(*(uint16_t*)(*((*s) + 2) + 2)) = backup2;

	byte backup3 = s[0][3][3];
	(*(uint32_t*)((*s) + 3)) <<= 8;
	s[0][3][0] = backup3;
}

void InvShiftRows(state* s) {
	//AES 解密关键步骤函数，左移  ref. P21 
	byte backup1 = s[0][1][3];
	(*(uint32_t*)((*s) + 1)) <<= 8;
	s[0][1][0] = backup1;

	uint16_t backup2 = (*(uint16_t*)((*s) + 2));
	(*(uint16_t*)((*s) + 2)) = (*(uint16_t*)(*((*s) + 2) + 2));
	(*(uint16_t*)(*((*s) + 2) + 2)) = backup2;

	byte backup3 = s[0][3][0];
	(*(uint32_t*)((*s) + 3)) >>= 8;
	s[0][3][3] = backup3;
}

//多项式乘以x（相当于系数序列左移以为或乘以2）在GF(2^8)的值
#define xtime(x) (((x<<1) ^ (((x>>7) & 1) * 0x1b)))

void MixColumns(state* s) {
	//AES 加密关键步骤函数，列操作，涉及到GF(2^8)域的乘法，  ref. P18 	
	for (uint8_t c = 0; c < 4; c++) {
		uint8_t t0 = (*s)[0][c];
		uint8_t t1 = (*s)[1][c];
		uint8_t t2 = (*s)[2][c];
		uint8_t t3 = (*s)[3][c];
		(*s)[0][c] = xtime(t0) ^ (t1 ^ xtime(t1)) ^ t2 ^ t3;
		(*s)[1][c] = t0 ^ xtime(t1) ^ (t2 ^ xtime(t2)) ^ t3;
		(*s)[2][c] = t0 ^ t1 ^ xtime(t2) ^ (t3 ^ xtime(t3));
		(*s)[3][c] = (t0 ^ xtime(t0)) ^ t1 ^ t2 ^ xtime(t3);
	}
	
}


//下面时两个多项式相乘的推导过程，两个多项式相乘最终能等效替代为多个xtime
//{57} * {13} = {fe}
//{57} * {02} = xtime({57}) = {ae}
//{57} * {04} = xtime({ae}) = {47}
//{57} * {08} = xtime({47}) = {8e}
//{57} * {10} = xtime({8e}) = {07}
//{57} * {13} = {57} * ({01} ^ {02} ^ {10})
//				{57} ^ {ae} ^ {07}
//				{fe}

#define multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

void InvMixColumns(state* s) {
	//AES 解密关键步骤函数，列逆操作，涉及到GF(2^8)域的乘法  ref. P23 
	for (uint8_t c = 0; c < 4; c++) {
		uint8_t t0 = (*s)[0][c];
		uint8_t t1 = (*s)[1][c];
		uint8_t t2 = (*s)[2][c];
		uint8_t t3 = (*s)[3][c];
		(*s)[0][c] = multiply(t0, 0x0e) ^ multiply(t1, 0x0b) ^ multiply(t2, 0x0d) ^ multiply(t3, 0x09);
		(*s)[1][c] = multiply(t0, 0x09) ^ multiply(t1, 0x0e) ^ multiply(t2, 0x0b) ^ multiply(t3, 0x0d);
		(*s)[2][c] = multiply(t0, 0x0d) ^ multiply(t1, 0x09) ^ multiply(t2, 0x0e) ^ multiply(t3, 0x0b);
		(*s)[3][c] = multiply(t0, 0x0b) ^ multiply(t1, 0x0d) ^ multiply(t2, 0x09) ^ multiply(t3, 0x0e);
	}

}

void AddRoundKey(state* s, word*key) {
	//AES 加解密关键步骤函数，异或轮密钥 ref. P18
	for (uint8_t r = 0; r < 4; r++) {
		for (uint8_t c = 0; c < 4; c++) {
			(*s)[r][c] ^= key[c][r];
		}
	}
}

void AESe(const state* S, state* outputS) {
	/*
	AES 加密函数，标准流程，伪代码请看 ref. P15
	@S: 输入的状态矩阵，大小为128位即16字节
	@outputS: 输出的状态矩阵，大小为128位即16字节
	*/
	assert(S != NULL && outputS != NULL && (Nr == 10 || Nr == 12 || Nr == 14));
	//printf("3,3:%02x\n", S[0][3][3]);
	memcpy(outputS, S, sizeof(state));
	AddRoundKey(outputS, keys);
	for (uint8_t round = 1; round <= Nr - 1; round++) {
		SubBytes(outputS);
		ShiftRows(outputS);
		MixColumns(outputS);
		AddRoundKey(outputS, keys + round * 4);
	}
	SubBytes(outputS);
	ShiftRows(outputS);
	AddRoundKey(outputS, keys + Nr * 4);
}

void AESd(const state* S, state* outputS) {
	/*
	AES 解密函数，标准流程，伪代码请看 ref. P21
	@S: 输入的状态矩阵，大小为128位即16字节
	@outputS: 输出的状态矩阵，大小为128位即16字节
	*/
	assert(S != NULL && outputS != NULL && (Nr == 10 || Nr == 12 || Nr == 14));
	memcpy(outputS, S, sizeof(state));
	AddRoundKey(outputS, keys + Nr * 4);
	for (uint8_t round = Nr - 1; round >= 1; round--) {
		InvShiftRows(outputS);
		InvSubBytes(outputS);
		AddRoundKey(outputS, keys + round * 4);
		InvMixColumns(outputS);
	}
	InvShiftRows(outputS);
	InvSubBytes(outputS);
	AddRoundKey(outputS, keys);
}

void cpy2state(state* S, byte* text, uint8_t Nb) {
	//将text复制到状态S矩阵中
	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < Nb; c++) {
			S[0][r][c] = text[r + 4 * c];
		}
	}
}

void cpyfromstate(byte* text, state* S, uint8_t Nb) {
	//从状态S矩阵中复制字符数组出来
	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < Nb; c++) {
			text[r + 4 * c] = S[0][r][c];
		}
	}
}

void ECBe(const byte* plaintext, const uint64_t plainlength, byte** ciphertext, uint64_t* cipherlength) {
	/*
	AES ECB模式加密函数，
	@plaintext: 输入的明文字符序列指针，
	@plainlength: 输入的明文字符序列长度（字节）
	@ciphertext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@cipherlength: 待输出的字符序列的长度
	*/
	state S = { 0 };
	state outputS = { 0 };
	state decryptoutputS = { 0 };
	uint64_t group = plainlength / 0x10 + (plainlength % 0x10 == 0 ? 0 : 1);
	*ciphertext = malloc(group * 0x10);
	*cipherlength = group * 0x10;
	for (int i = 0; i < group; i++) {
		cpy2state(&S, plaintext+i*0x10, 4);
		//printf("2,1:%02x\nplain[6]:%02x\n", S[2][1],plaintext[6 + i * 0x10]);
		AESe(&S, &outputS);
		//AESd(&outputS, &decryptoutputS);
		//assert(memcmp(&S, &decryptoutputS, sizeof(state)) == 0);
		cpyfromstate(*ciphertext + i * 0x10, &outputS, 4);
	}
	return;
}

void CBCe(const byte* plaintext, const uint64_t plainlength, const byte* vitext, byte** ciphertext, uint64_t* cipherlength) {
	/*
	AES CBC模式加密函数，
	@plaintext: 输入的明文字符序列指针，
	@plainlength: 输入的明文字符序列长度（字节）
	@ciphertext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@cipherlength: 待输出的字符序列的长度
	*/

	byte C[16] = { 0 };
	memcpy(C, vitext, 0x10);

	state S = { 0 };
	state outputS = { 0 };
	state decryptoutputS = { 0 };
	uint64_t group = plainlength / 0x10 + (plainlength % 0x10 == 0 ? 0 : 1);
	*ciphertext = malloc(group * 0x10);
	*cipherlength = group * 0x10;
	for (int i = 0; i < group; i++) {
		*((uint64_t*)C) = *((uint64_t*)C) ^ *((uint64_t*)(plaintext + i * 0x10));
		*(((uint64_t*)C) + 1) = *(((uint64_t*)C) + 1) ^ *(((uint64_t*)(plaintext + i * 0x10)) + 1);
		cpy2state(&S, C, 4);
		//printf("2,1:%02x\nplain[6]:%02x\n", S[2][1],plaintext[6 + i * 0x10]);
		AESe(&S, &outputS);
		AESd(&outputS, &decryptoutputS);
		assert(memcmp(&S, &decryptoutputS, sizeof(state)) == 0);
		cpyfromstate(*ciphertext + i * 0x10, &outputS, 4);
		memcpy(C, *ciphertext + i * 0x10, 0x10);
	}
	return;
}

void CFBe(const byte* plaintext, const uint64_t plainlength, const byte* vitext, byte** ciphertext, uint64_t* cipherlength) {
	/*
	AES CFB模式加密函数，
	@plaintext: 输入的明文字符序列指针，
	@plainlength: 输入的明文字符序列长度（字节）
	@ciphertext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@cipherlength: 待输出的字符序列的长度
	*/
	state S = { 0 };
	state outputS = { 0 };
	state decryptoutputS = { 0 };
	char reg[0x10] = { 0 };
	char desoutput[0x10] = { 0 };
	memcpy(reg, vitext, 0x10);
	*ciphertext = malloc(plainlength);
	*cipherlength = plainlength;
	memset(*ciphertext, 0, plainlength);

	for (int i = 0; i < plainlength; i++) {
		cpy2state(&S, reg, 4);
		//printf("2,1:%02x\nplain[6]:%02x\n", S[2][1],plaintext[6 + i * 0x10]);
		AESe(&S, &outputS);
		AESd(&outputS, &decryptoutputS);
		assert(memcmp(&S, &decryptoutputS, sizeof(state)) == 0);
		cpyfromstate(desoutput, &outputS, 4);
		byte C = *(plaintext + i) ^ *desoutput;
		*(*ciphertext + i) = C;
		for (int j = 0; j < 0x10 - 1; j++) {
			reg[j] = reg[j + 1];
		}
		reg[0x10 - 1] = C;
	}
}

void OFBe(const byte* plaintext, const uint64_t plainlength, const byte* vitext, byte** ciphertext, uint64_t* cipherlength) {
	/*
	AES OFB模式加密函数，
	@plaintext: 输入的明文字符序列指针，
	@plainlength: 输入的明文字符序列长度（字节）
	@ciphertext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@cipherlength: 待输出的字符序列的长度
	*/
	state S = { 0 };
	state outputS = { 0 };
	state decryptoutputS = { 0 };
	char reg[0x10] = { 0 };
	char desoutput[0x10] = { 0 };
	memcpy(reg, vitext, 0x10);
	*ciphertext = malloc(plainlength);
	*cipherlength = plainlength;
	memset(*ciphertext, 0, plainlength);

	for (int i = 0; i < plainlength; i++) {
		cpy2state(&S, reg, 4);
		//printf("2,1:%02x\nplain[6]:%02x\n", S[2][1],plaintext[6 + i * 0x10]);
		AESe(&S, &outputS);
		AESd(&outputS, &decryptoutputS);
		assert(memcmp(&S, &decryptoutputS, sizeof(state)) == 0);
		cpyfromstate(desoutput, &outputS, 4);
		byte C = *(plaintext + i) ^ *desoutput;
		*(*ciphertext + i) = C;
		for (int j = 0; j < 0x10 - 1; j++) {
			reg[j] = reg[j + 1];
		}
		reg[0x10 - 1] = *desoutput;
	}
}

void ECBd(const byte* ciphertext, const uint64_t cipherlength, byte** plaintext, uint64_t* plainlength) {
	/*
	DES ECB模式解密函数，
	@ciphertext: 输入的密文字符序列指针，
	@cipherlength: 输入的密文字符序列长度（字节）
	@plaintext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@plainlength:待输出的字符序列的长度
	*/
	
	state S = { 0 };
	state outputS = { 0 };
	state encryptoutputS = { 0 };
	uint64_t group = cipherlength / 0x10 + (cipherlength % 0x10 == 0 ? 0 : 1);
	*plaintext = malloc(group * 0x10);
	*plainlength = group * 0x10;
	for (int i = 0; i < group; i++) {
		cpy2state(&S, ciphertext + i * 0x10, 4);
		//printf("2,1:%02x\nplain[6]:%02x\n", S[2][1],plaintext[6 + i * 0x10]);
		AESd(&S, &outputS);
		//AESe(&outputS, &encryptoutputS);
		//assert(memcmp(&S, &encryptoutputS, sizeof(state)) == 0);
		cpyfromstate(*plaintext + i * 0x10, &outputS, 4);
	}
	return;

}

void CBCd(const byte* ciphertext, const uint64_t cipherlength, const byte* vitext, byte** plaintext, uint64_t* plainlength) {
	/*
	DES CBC模式解密函数，
	@ciphertext: 输入的密文字符序列指针，
	@cipherlength: 输入的密文字符序列长度（字节）
	@vitext: 输入的初始化向量字符序列指针
	@plaintext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@plainlength:待输出的字符序列的长度
	*/
	byte C[0x10] = { 0 };
	memcpy(C, vitext, 0x10);

	state S = { 0 };
	state encryptoutputS = { 0 };
	byte output[0x10];
	uint64_t group = cipherlength / 0x10 + (cipherlength % 0x10 == 0 ? 0 : 1);
	*plaintext = malloc(group * 0x10);
	*plainlength = group * 0x10;
	for (int i = 0; i < group; i++) {
		cpy2state(&S, C, 4);
		AESd(&S, &encryptoutputS);
		cpyfromstate(output, &encryptoutputS, 4);
		for (int j = 0; j < 0x10; j++) {
			*(*plaintext + 0x10 * i + j) = C[j] ^ output[j];
		}
		
		memcpy(C, ciphertext + i * 0x10, 0x10);
	}
	return;
}

void CFBd(const byte* ciphertext, const uint64_t cipherlength, const byte* vitext, byte** plaintext, uint64_t* plainlength) {
	/*
	DES CFB模式解密函数，
	@ciphertext: 输入的密文字符序列指针，
	@cipherlength: 输入的密文字符序列长度（字节）
	@vitext: 输入的初始化向量字符序列指针
	@plaintext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@plainlength:待输出的字符序列的长度
	*/

	state S = { 0 };
	state outputS = { 0 };

	char reg[0x10] = { 0 };
	char desoutput[0x10] = { 0 };
	memcpy(reg, vitext, 0x10);
	//int cipherlength = strlen(ciphertext);
	*plaintext = malloc(cipherlength);
	*plainlength = cipherlength;
	memset(*plaintext, 0, cipherlength);

	for (int i = 0; i < cipherlength; i++) {
		cpy2state(&S, reg, 4);
		//printf("2,1:%02x\nplain[6]:%02x\n", S[2][1],plaintext[6 + i * 0x10]);
		AESe(&S, &outputS);
		cpyfromstate(desoutput, &outputS, 4);
		byte M = *(ciphertext + i) ^ *desoutput;
		*(*plaintext + i) = M;
		for (int j = 0; j < 0x10 - 1; j++) {
			reg[j] = reg[j + 1];
		}
		reg[0x10 - 1] = *(ciphertext + i);
	}
}

void OFBd(const byte* ciphertext, const uint64_t cipherlength, const byte* vitext, byte** plaintext, uint64_t* plainlength) {
	/*
	DES OFB模式解密函数，
	@ciphertext: 输入的密文字符序列指针，
	@cipherlength: 输入的密文字符序列长度（字节）
	@vitext: 输入的初始化向量字符序列指针
	@plaintext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@plainlength:待输出的字符序列的长度
	*/
	state S = { 0 };
	state outputS = { 0 };

	char reg[0x10] = { 0 };
	char desoutput[0x10] = { 0 };
	memcpy(reg, vitext, 0x10);
	//int cipherlength = strlen(ciphertext);
	*plaintext = malloc(cipherlength);
	*plainlength = cipherlength;
	memset(*plaintext, 0, cipherlength);

	for (int i = 0; i < cipherlength; i++) {
		cpy2state(&S, reg, 4);
		//printf("2,1:%02x\nplain[6]:%02x\n", S[2][1],plaintext[6 + i * 0x10]);
		AESe(&S, &outputS);
		cpyfromstate(desoutput, &outputS, 4);
		byte M = *(ciphertext + i) ^ *desoutput;
		*(*plaintext + i) = M;
		for (int j = 0; j < 0x10 - 1; j++) {
			reg[j] = reg[j + 1];
		}
		reg[0x10 - 1] = *desoutput;
	}
}

void benchmark() {
	/*
	性能测试函数
	*/
	uint64_t plaintextlength = 5 * 1024 * 1024;
	byte* plaintext = malloc(plaintextlength);
	memset(plaintext, 1, plaintextlength);
	//byte key[0x10] = { 0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef };
	clock_t starttime, endtime;
	starttime = clock();
	for (int i = 0; i < 20; i++) {
		byte* plain;
		uint64_t plainlen;
		byte* cipher;
		uint64_t cipherlen;
		ECBe(plaintext, plaintextlength, &cipher, &cipherlen);
		ECBd(cipher, cipherlen, &plain, &plainlen);
		free(plain);
		free(cipher);
	}
	endtime = clock();
	printf("ECB耗时：%02f秒", (endtime - starttime) / 1000.0);
}

int main(int argc, char** argv) {

	printf("argc:%d\n", argc);
	for (int i = 0; i < argc; i++) {
		printf("%d : %s\n", i, argv[i]);
	}

	/*
	-p plainfile 指定明文文件的位置和名称
	-k keyfile  指定密钥文件的位置和名称
	-v vifile  指定初始化向量文件的位置和名称
	-m mode  指定加密的操作模式
	-c cipherfile 指定密文文件的位置和名称。
	*/

	if (argc % 2 == 0) {
		print_usage();
	}

	for (int i = 1; i < argc; i += 2) {
		if (strlen(argv[i]) != 2) {
			print_usage();
		}
		switch (argv[i][1]) {
		case 'p':
			plainfile = argv[i + 1];
			break;
		case 'k':
			keyfile = argv[i + 1];
			break;
		case 'v':
			vifile = argv[i + 1];
			break;
		case 'm':
			if (strcmp(argv[i + 1], AES_MODE[0]) != 0 && strcmp(argv[i + 1], AES_MODE[1]) != 0 && strcmp(argv[i + 1], AES_MODE[2]) != 0 && strcmp(argv[i + 1], AES_MODE[3]) != 0) {
				print_usage();
			}
			mode = argv[i + 1];
			break;
		case 'c':
			cipherfile = argv[i + 1];
			break;
		default:
			print_usage();
		}
	}

	if (plainfile == NULL || keyfile == NULL || mode == NULL || cipherfile == NULL) {
		print_usage();
	}

	if (strcmp(mode, "ECB") != 0 && vifile == NULL) {
		print_usage();
	}

	printf("解析参数完成！\n");
	printf("参数为明文文件的位置和名称:%s\n", plainfile);
	printf("参数为密钥文件的位置和名称:%s\n", keyfile);
	if (strcmp(mode, "ECB") != 0) {
		printf("参数为初始化向量文件文件的位置和名称:%s\n", vifile);
	}
	printf("参数为密文文件的位置和名称:%s\n", cipherfile);
	printf("参数为加密的模式:%s\n", mode);

	printf("现在开始读取文件！\n");

	printf("读取明文文件...\n");
	bool read_result = readfile2memory(plainfile, &plaintext, &plaintextlength);
	if (read_result == false) {
		printf("读取明文文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取明文文件成功！\n");

	printf("读取密钥文件...\n");
	read_result = readfile2memory(keyfile, &keytext, &keytextlength);
	if (read_result == false) {
		printf("读取密钥文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取密钥文件成功！\n");

	//在密钥文件读取后，可以初始化全局变量了，
	Nr = (keytextlength == 0x10 ? 10 : (keytextlength == 0x18 ? 12 : 14));
	Nk = (keytextlength == 0x10 ? 4 : (keytextlength == 0x18 ? 6 : 8));
	//然后生成轮密钥，keys为全局变量！
	KeyExpansion(keytext, keys, Nk);

	if (strcmp(mode, "ECB") != 0) {
		printf("读取初始向量文件...\n");
		read_result = readfile2memory(vifile, &vitext, &vitextlegnth);
		if (read_result == false) {
			printf("读取初始向量文件失败，请检查路径及文件是否存在\n");
			exit(-1);
		}
		printf("读取初始向量文件成功！\n");
	}

	if (strcmp(mode, "ECB") == 0) {
		ECBe(plaintext, plaintextlength, &ciphertext, &ciphertextlength);
		byte* p;
		uint64_t pl;
		ECBd(ciphertext, ciphertextlength, &p, &pl);
	}
	else if (strcmp(mode, "CBC") == 0) {
		CBCe(plaintext, plaintextlength, vitext, &ciphertext, &ciphertextlength);
		byte* p;
		uint64_t pl;
		CBCd(ciphertext, ciphertextlength, vitext, &p, &pl);
	}
	else if (strcmp(mode, "CFB") == 0) {
		CFBe(plaintext, plaintextlength, vitext, &ciphertext, &ciphertextlength);
		byte* p;
		uint64_t pl;
		CFBd(ciphertext, ciphertextlength, vitext, &p, &pl);
	}
	else if (strcmp(mode, "OFB") == 0) {
		OFBe(plaintext, plaintextlength, vitext, &ciphertext, &ciphertextlength);
		byte* p;
		uint64_t pl;
		OFBd(ciphertext, ciphertextlength, vitext, &p, &pl);
	}
	else {
		//不应该能到达这里
		printf("致命错误！！！\n");
		exit(-2);
	}


	if (ciphertext == NULL) {
		printf("同学，ciphertext没有分配内存哦，需要补补基础~\n失败，程序退出中...");
		exit(-1);
	}

	//printf("解密出来的字符串为:%s\n", ciphertext);
	printf("16进制表示为:");

	int count = ciphertextlength;
	byte* cipherhex = malloc(count * 2);
	memset(cipherhex, 0, count * 2);

	for (int i = 0; i < count; i++) {
		sprintf(cipherhex + i * 2, "%02X", ciphertext[i]);
	}
	printf("%s\n写入文件中...\n", cipherhex);

	FILE* fp = fopen(cipherfile, "w");
	if (fp == NULL) {
		printf("文件 %s 打开失败,请检查", cipherfile);
		exit(-1);
	}

	int writecount = fwrite(cipherhex, count * 2, 1, fp);
	if (writecount != 1) {
		printf("写入文件出现故障，请重新尝试！");
		fclose(fp);
		exit(-1);
	}
	fclose(fp);
	printf("正在进行性能测试！\n");
	benchmark();//性能测试
	printf("恭喜你完成了该程序，请提交代码!");

    return 0;
}