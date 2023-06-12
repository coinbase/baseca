-- init-docker.sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
INSERT INTO users (uuid, username, hashed_credential, full_name, email, permissions, credential_changed_at)
VALUES (uuid_generate_v4(), 'defaultuser', crypt('defaultpassword', gen_salt('bf')), 'Default User', 'defaultuser@example.com', 'ADMIN', now());
