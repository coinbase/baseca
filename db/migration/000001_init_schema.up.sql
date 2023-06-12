CREATE TABLE "users" (
  "uuid" uuid UNIQUE PRIMARY KEY,
  "username" varchar UNIQUE NOT NULL,
  "hashed_credential" varchar NOT NULL,
  "full_name" varchar NOT NULL,
  "email" varchar UNIQUE NOT NULL,
  "permissions" varchar NOT NULL,
  "credential_changed_at" timestamptz NOT NULL DEFAULT '0001-01-01 00:00:00Z',
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "accounts" (
  "client_id" uuid UNIQUE PRIMARY KEY,
  "api_token" varchar NOT NULL,
  "service_account" varchar NOT NULL,
  "environment" varchar NOT NULL,
  "team" varchar NOT NULL,
  "email" varchar NOT NULL,
  "regular_expression" varchar,
  "valid_subject_alternate_name" varchar[] NOT NULL,
  "valid_certificate_authorities" varchar[] NOT NULL,
  "extended_key" varchar NOT NULL,
  "certificate_validity" smallserial NOT NULL,
  "subordinate_ca" varchar NOT NULL,
  "node_attestation" varchar[],
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "created_by" uuid NOT NULL
);

CREATE TABLE "certificates" (
  "serial_number" varchar PRIMARY KEY,
  "account" varchar NOT NULL,
  "environment" varchar NOT NULL,
  "extended_key" varchar NOT NULL,
  "common_name" varchar NOT NULL,
  "subject_alternative_name" varchar[] NOT NULL,
  "expiration_date" timestamptz NOT NULL DEFAULT (now()),
  "issued_date" timestamptz NOT NULL DEFAULT (now()),
  "revoked" boolean NOT NULL DEFAULT false,
  "revoked_by" varchar,
  "revoke_date" timestamptz,
  "certificate_authority_arn" varchar
);

CREATE TABLE "aws_attestation" (
  "client_id" uuid UNIQUE PRIMARY KEY,
  "role_arn" varchar,
  "assume_role" varchar,
  "security_group_id" varchar[],
  "region" varchar,
  "instance_id" varchar,
  "image_id" varchar,
  "instance_tags" json
);

CREATE TABLE "provisioners" (
  "client_id" uuid UNIQUE PRIMARY KEY,
  "api_token" varchar NOT NULL,
  "provisioner_account" varchar NOT NULL,
  "environments" varchar[] NOT NULL,
  "team" varchar NOT NULL,
  "email" varchar NOT NULL,
  "regular_expression" varchar,
  "valid_subject_alternate_names" varchar[] NOT NULL,
  "extended_keys" varchar[] NOT NULL,
  "max_certificate_validity" smallserial NOT NULL,
  "node_attestation" varchar[],
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "created_by" uuid NOT NULL
);

ALTER TABLE "accounts" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("uuid");
ALTER TABLE "provisioners" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("uuid");