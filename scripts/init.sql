CREATE USER superdevuser;
CREATE DATABASE superdevdb;
GRANT ALL PRIVILEGES ON DATABASE superdevdb TO superdevuser;
ALTER USER postgres with PASSWORD '12345678';
ALTER USER superdevuser with PASSWORD '12345678';