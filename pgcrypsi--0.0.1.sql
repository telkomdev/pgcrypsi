\echo Use "CREATE EXTENSION pgcrypsi" to load this file. \quit
CREATE FUNCTION pgcrypsi_aes_128_gcm_encrypt(text, text) RETURNS text
AS 'MODULE_PATHNAME', 'pgcrypsi_aes_128_gcm_encrypt' 
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgcrypsi_aes_192_gcm_encrypt(text, text) RETURNS text
AS 'MODULE_PATHNAME', 'pgcrypsi_aes_192_gcm_encrypt' 
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgcrypsi_aes_256_gcm_encrypt(text, text) RETURNS text
AS 'MODULE_PATHNAME', 'pgcrypsi_aes_256_gcm_encrypt' 
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgcrypsi_aes_128_gcm_decrypt(text, text) RETURNS text
AS 'MODULE_PATHNAME', 'pgcrypsi_aes_128_gcm_decrypt' 
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgcrypsi_aes_192_gcm_decrypt(text, text) RETURNS text
AS 'MODULE_PATHNAME', 'pgcrypsi_aes_192_gcm_decrypt' 
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgcrypsi_aes_256_gcm_decrypt(text, text) RETURNS text
AS 'MODULE_PATHNAME', 'pgcrypsi_aes_256_gcm_decrypt' 
LANGUAGE C IMMUTABLE STRICT;