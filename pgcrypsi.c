/*
The MIT License (MIT)

Copyright (c) 2023 The TelkomDev Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include <string.h>
#include "crypsi.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(pgcrypsi_aes_128_gcm_encrypt);
Datum pgcrypsi_aes_128_gcm_encrypt(PG_FUNCTION_ARGS)
{   
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1)) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key and input_text are not allowed")
            )
        );
    }

    text* input_key = PG_GETARG_TEXT_PP(0);
    text* input_text = PG_GETARG_TEXT_PP(1);

    int32  key_size = VARSIZE_ANY_EXHDR(input_key);
    int32  text_size = VARSIZE_ANY_EXHDR(input_text);
    elog(NOTICE, "key_size %d", key_size);
    elog(NOTICE, "text_size %d", text_size);

    if (key_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key are not allowed")
            )
        );
    }

    if (text_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_text are not allowed")
            )
        );
    }

    int ret = 0;
    char* input_key_cleaned = text_to_cstring(input_key);
    char* input_text_cleaned = text_to_cstring(input_text);

    unsigned char* dst = NULL;
    int dst_size = 0;
    ret = crypsi_aes_128_gcm_encrypt(input_key_cleaned, input_text_cleaned, text_size, &dst, &dst_size);
    if (ret != 0)
    {
        ereport(ERROR,
            (errcode(ERRCODE_DATA_EXCEPTION),
                errmsg("error encrypt with crypsi_aes_128_gcm_encrypt")
            )
        );
    }

    char* result = palloc(dst_size + 1);
    memcpy((void*) result, (void*) dst, dst_size);
    result[dst_size] = '\0';

    free((void*) dst);
    PG_RETURN_TEXT_P(cstring_to_text(result));
}

PG_FUNCTION_INFO_V1(pgcrypsi_aes_192_gcm_encrypt);
Datum pgcrypsi_aes_192_gcm_encrypt(PG_FUNCTION_ARGS)
{   
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1)) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key and input_text are not allowed")
            )
        );
    }

    text* input_key = PG_GETARG_TEXT_PP(0);
    text* input_text = PG_GETARG_TEXT_PP(1);

    int32  key_size = VARSIZE_ANY_EXHDR(input_key);
    int32  text_size = VARSIZE_ANY_EXHDR(input_text);

    if (key_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key are not allowed")
            )
        );
    }

    if (text_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_text are not allowed")
            )
        );
    }

    int ret = 0;
    char* input_key_cleaned = text_to_cstring(input_key);
    char* input_text_cleaned = text_to_cstring(input_text);

    unsigned char* dst = NULL;
    int dst_size = 0;
    ret = crypsi_aes_192_gcm_encrypt(input_key_cleaned, input_text_cleaned, text_size, &dst, &dst_size);
    if (ret != 0)
    {
        ereport(ERROR,
            (errcode(ERRCODE_DATA_EXCEPTION),
                errmsg("error encrypt with crypsi_aes_192_gcm_encrypt")
            )
        );
    }

    char* result = palloc(dst_size + 1);
    memcpy((void*) result, (void*) dst, dst_size);
    result[dst_size] = '\0';

    free((void*) dst);
    PG_RETURN_TEXT_P(cstring_to_text(result));
}

PG_FUNCTION_INFO_V1(pgcrypsi_aes_256_gcm_encrypt);
Datum pgcrypsi_aes_256_gcm_encrypt(PG_FUNCTION_ARGS)
{   
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1)) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key and input_text are not allowed")
            )
        );
    }

    text* input_key = PG_GETARG_TEXT_PP(0);
    text* input_text = PG_GETARG_TEXT_PP(1);

    int32  key_size = VARSIZE_ANY_EXHDR(input_key);
    int32  text_size = VARSIZE_ANY_EXHDR(input_text);

    if (key_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key are not allowed")
            )
        );
    }

    if (text_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_text are not allowed")
            )
        );
    }

    int ret = 0;
    char* input_key_cleaned = text_to_cstring(input_key);
    char* input_text_cleaned = text_to_cstring(input_text);

    unsigned char* dst = NULL;
    int dst_size = 0;
    ret = crypsi_aes_256_gcm_encrypt(input_key_cleaned, input_text_cleaned, text_size, &dst, &dst_size);
    if (ret != 0)
    {
        ereport(ERROR,
            (errcode(ERRCODE_DATA_EXCEPTION),
                errmsg("error encrypt with crypsi_aes_256_gcm_encrypt")
            )
        );
    }

    char* result = palloc(dst_size + 1);
    memcpy((void*) result, (void*) dst, dst_size);
    result[dst_size] = '\0';

    free((void*) dst);
    PG_RETURN_TEXT_P(cstring_to_text(result));
}

PG_FUNCTION_INFO_V1(pgcrypsi_aes_128_gcm_decrypt);
Datum pgcrypsi_aes_128_gcm_decrypt(PG_FUNCTION_ARGS)
{   
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1)) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key and input_text are not allowed")
            )
        );
    }

    text* input_key = PG_GETARG_TEXT_PP(0);
    text* input_text = PG_GETARG_TEXT_PP(1);

    int32  key_size = VARSIZE_ANY_EXHDR(input_key);
    int32  text_size = VARSIZE_ANY_EXHDR(input_text);

    if (key_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key are not allowed")
            )
        );
    }

    if (text_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_text are not allowed")
            )
        );
    }

    int ret = 0;
    char* input_key_cleaned = text_to_cstring(input_key);
    char* input_text_cleaned = text_to_cstring(input_text);

    unsigned char* dst = NULL;
    int dst_size = 0;
    ret = crypsi_aes_128_gcm_decrypt(input_key_cleaned, input_text_cleaned, text_size, &dst, &dst_size);
    if (ret != 0)
    {
        ereport(ERROR,
            (errcode(ERRCODE_DATA_EXCEPTION),
                errmsg("error decrypt with crypsi_aes_128_gcm_decrypt")
            )
        );
    }

    char* result = palloc(dst_size + 1);
    memcpy((void*) result, (void*) dst, dst_size);
    result[dst_size] = '\0';

    free((void*) dst);
    PG_RETURN_TEXT_P(cstring_to_text(result));
}

PG_FUNCTION_INFO_V1(pgcrypsi_aes_192_gcm_decrypt);
Datum pgcrypsi_aes_192_gcm_decrypt(PG_FUNCTION_ARGS)
{   
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1)) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key and input_text are not allowed")
            )
        );
    }

    text* input_key = PG_GETARG_TEXT_PP(0);
    text* input_text = PG_GETARG_TEXT_PP(1);

    int32  key_size = VARSIZE_ANY_EXHDR(input_key);
    int32  text_size = VARSIZE_ANY_EXHDR(input_text);

    if (key_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key are not allowed")
            )
        );
    }

    if (text_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_text are not allowed")
            )
        );
    }

    int ret = 0;
    char* input_key_cleaned = text_to_cstring(input_key);
    char* input_text_cleaned = text_to_cstring(input_text);

    unsigned char* dst = NULL;
    int dst_size = 0;
    ret = crypsi_aes_192_gcm_decrypt(input_key_cleaned, input_text_cleaned, text_size, &dst, &dst_size);
    if (ret != 0)
    {
        ereport(ERROR,
            (errcode(ERRCODE_DATA_EXCEPTION),
                errmsg("error decrypt with crypsi_aes_192_gcm_decrypt")
            )
        );
    }

    char* result = palloc(dst_size + 1);
    memcpy((void*) result, (void*) dst, dst_size);
    result[dst_size] = '\0';

    free((void*) dst);
    PG_RETURN_TEXT_P(cstring_to_text(result));
}

PG_FUNCTION_INFO_V1(pgcrypsi_aes_256_gcm_decrypt);
Datum pgcrypsi_aes_256_gcm_decrypt(PG_FUNCTION_ARGS)
{   
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1)) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key and input_text are not allowed")
            )
        );
    }

    text* input_key = PG_GETARG_TEXT_PP(0);
    text* input_text = PG_GETARG_TEXT_PP(1);

    int32  key_size = VARSIZE_ANY_EXHDR(input_key);
    int32  text_size = VARSIZE_ANY_EXHDR(input_text);

    if (key_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_key are not allowed")
            )
        );
    }

    if (text_size <= 0) 
    {
        ereport(ERROR,
            (errcode(ERRCODE_STRING_DATA_LENGTH_MISMATCH),
                errmsg("empty input_text are not allowed")
            )
        );
    }

    int ret = 0;
    char* input_key_cleaned = text_to_cstring(input_key);
    char* input_text_cleaned = text_to_cstring(input_text);

    unsigned char* dst = NULL;
    int dst_size = 0;
    ret = crypsi_aes_256_gcm_decrypt(input_key_cleaned, input_text_cleaned, text_size, &dst, &dst_size);
    if (ret != 0)
    {
        ereport(ERROR,
            (errcode(ERRCODE_DATA_EXCEPTION),
                errmsg("error decrypt with crypsi_aes_256_gcm_decrypt")
            )
        );
    }

    char* result = palloc(dst_size + 1);
    memcpy((void*) result, (void*) dst, dst_size);
    result[dst_size] = '\0';

    free((void*) dst);
    PG_RETURN_TEXT_P(cstring_to_text(result));
}