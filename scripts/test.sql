-- test should return a value of "t", which means the test cases are working as expected --

-- AES GCM test --
select 'hello world' = pgcrypsi_aes_128_gcm_decrypt('abc$#128djdyAgbj', pgcrypsi_aes_128_gcm_encrypt('abc$#128djdyAgbj', 'hello world')) as res_pgcrypsi_aes_128_gcm_decrypt_valid;
select 'hello world' = pgcrypsi_aes_192_gcm_decrypt('abc$#128djdyAgbjau&YAnmc', pgcrypsi_aes_192_gcm_encrypt('abc$#128djdyAgbjau&YAnmc', 'hello world')) as res_pgcrypsi_aes_192_gcm_decrypt_valid;
select 'hello world' = pgcrypsi_aes_256_gcm_decrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', pgcrypsi_aes_256_gcm_encrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello world')) as res_pgcrypsi_aes_256_gcm_decrypt_valid;

select 'hello world' != pgcrypsi_aes_128_gcm_decrypt('abc$#128djdyAgbj', pgcrypsi_aes_128_gcm_encrypt('abc$#128djdyAgbj', 'hello worldie')) as res_pgcrypsi_aes_128_gcm_decrypt_invalid;
select 'hello world' != pgcrypsi_aes_192_gcm_decrypt('abc$#128djdyAgbjau&YAnmc', pgcrypsi_aes_192_gcm_encrypt('abc$#128djdyAgbjau&YAnmc', 'hello worldie')) as res_pgcrypsi_aes_192_gcm_decrypt_invalid;
select 'hello world' != pgcrypsi_aes_256_gcm_decrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', pgcrypsi_aes_256_gcm_encrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', 'hello worldie')) as res_pgcrypsi_aes_256_gcm_decrypt_invalid;