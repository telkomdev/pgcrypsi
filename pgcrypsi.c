#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include <string.h>
#include "crypsi.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(crypsi_aes_128_gcm_encrypt);
Datum crypsi_aes_128_gcm_encrypt(PG_FUNCTION_ARGS)
{   
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
    int ret = crypsi_aes_128_gcm_encrypt(input_key_cleaned, input_text_cleaned, 0, &dst, &dst_size);
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

PG_FUNCTION_INFO_V1(crypsi_aes_192_gcm_encrypt);
Datum crypsi_aes_192_gcm_encrypt(PG_FUNCTION_ARGS)
{   
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
    int ret = crypsi_aes_192_gcm_encrypt(input_key_cleaned, input_text_cleaned, 0, &dst, &dst_size);
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

PG_FUNCTION_INFO_V1(crypsi_aes_256_gcm_encrypt);
Datum crypsi_aes_256_gcm_encrypt(PG_FUNCTION_ARGS)
{   
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
    int ret = crypsi_aes_256_gcm_encrypt(input_key_cleaned, input_text_cleaned, 0, &dst, &dst_size);
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

PG_FUNCTION_INFO_V1(crypsi_aes_128_gcm_decrypt);
Datum crypsi_aes_128_gcm_decrypt(PG_FUNCTION_ARGS)
{   
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
    int ret = crypsi_aes_128_gcm_decrypt(input_key_cleaned, input_text_cleaned, 0, &dst, &dst_size);
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

PG_FUNCTION_INFO_V1(crypsi_aes_192_gcm_decrypt);
Datum crypsi_aes_192_gcm_decrypt(PG_FUNCTION_ARGS)
{   
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
    int ret = crypsi_aes_192_gcm_decrypt(input_key_cleaned, input_text_cleaned, 0, &dst, &dst_size);
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

PG_FUNCTION_INFO_V1(crypsi_aes_256_gcm_decrypt);
Datum crypsi_aes_256_gcm_decrypt(PG_FUNCTION_ARGS)
{   
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
    int ret = crypsi_aes_256_gcm_decrypt(input_key_cleaned, input_text_cleaned, 0, &dst, &dst_size);
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