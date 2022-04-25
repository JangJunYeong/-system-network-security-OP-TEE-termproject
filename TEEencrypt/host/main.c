/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char encryptedkey[4] = {0,};
	int cut = 0;
	int len = 64;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
	/*res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ADD1, &op,
				 &err_origin);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ADD2, &op,
				 &err_origin);*/

	if(!strcmp(argv[1],"-e"))
	{
		printf("========================Encryption========================\n");
		char name[64] = {0,};
		memcpy(name, argv[2], 64);
		strcat(name,".txt");
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		FILE *fp1 = fopen(name, "r");
		FILE *fp2 = fopen("ciphertext.txt", "w");
		FILE *fp3 = fopen("encryptedkey.txt", "w");
		while (feof(fp1) == 0)
		{
			if(fgets(plaintext, sizeof(plaintext), fp1) == NULL)break;
			cut = strlen(plaintext);
			memcpy(op.params[0].tmpref.buffer, plaintext, len);
			printf("Invoking TA %s\n", op.params[0].tmpref.buffer);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
						 &err_origin);
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			ciphertext[cut] = '\0';
			printf("Ciphertext : %s\n", ciphertext);
			fputs(ciphertext, fp2);
			encryptedkey[0] = ciphertext[cut+1];
			encryptedkey[1] = ciphertext[cut+2];
			encryptedkey[2] = '\n';
			printf("Encryptedkey : %s\n", encryptedkey);
			fputs(encryptedkey, fp3);
		}
		fclose(fp1);
		fclose(fp2);
		fclose(fp3);
	}
	else if(!strcmp(argv[1],"-d"))
	{
		printf("========================Decryption========================\n");
		char name1[64] = {0,};
		memcpy(name1, argv[2], 64);
		strcat(name1,".txt");
		printf("name1 : %s\n", name1);
		char name2[64] = {0,};
		memcpy(name2, argv[3], 64);
		strcat(name2,".txt");
		printf("name2 : %s\n", name2);
		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = len;
		FILE *fp1 = fopen(name1, "r");
		FILE *fp2 = fopen(name2, "r");
		FILE *fp3 = fopen("dec.txt", "w");
		while (feof(fp1) == 0)
		{
			if(fgets(ciphertext, sizeof(ciphertext), fp1) == NULL)break;
			printf("Ciphertext : %s\n", ciphertext);
			fgets(encryptedkey, sizeof(encryptedkey), fp2);
			printf("Encryptedkey : %s\n", encryptedkey);
			strcat(ciphertext,encryptedkey);
			printf("Input : %s\n", ciphertext);
			memcpy(op.params[0].tmpref.buffer, ciphertext, len);
			printf("Invoking TA %s\n", op.params[0].tmpref.buffer);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
						 &err_origin);
			memcpy(plaintext, op.params[0].tmpref.buffer, len);
			printf("Plaintext : %s\n", plaintext);
			fputs(plaintext, fp3);
		}
		fclose(fp1);
		fclose(fp2);
		fclose(fp3);
	}
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
