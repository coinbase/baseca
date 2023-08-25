CREATE TABLE "users" (
  "uuid" uuid UNIQUE PRIMARY KEY,
  "username" varchar(100) UNIQUE NOT NULL,
  "hashed_credential" varchar(100) NOT NULL,
  "full_name" varchar(100) NOT NULL,
  "email" varchar(100) UNIQUE NOT NULL,
  "permissions" varchar(100) NOT NULL,
  "credential_changed_at" timestamptz NOT NULL DEFAULT '0001-01-01 00:00:00Z',
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "accounts" (
  "client_id" uuid UNIQUE PRIMARY KEY,
  "api_token" varchar(100) NOT NULL,
  "service_account" varchar(100) NOT NULL,
  "environment" varchar(100) NOT NULL,
  "team" varchar(100) NOT NULL,
  "email" varchar(100) NOT NULL,
  "regular_expression" varchar(100),
  "valid_subject_alternate_name" varchar(100)[] NOT NULL,
  "valid_certificate_authorities" varchar(100)[] NOT NULL,
  "extended_key" varchar(100) NOT NULL,
  "certificate_validity" smallserial NOT NULL,
  "subordinate_ca" varchar(100) NOT NULL,
  "provisioned" boolean NOT NULL,
  "node_attestation" varchar(100)[],
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "created_by" uuid NOT NULL
);

CREATE TABLE "certificates" (
  "serial_number" varchar(100) PRIMARY KEY,
  "account" varchar(100) NOT NULL,
  "environment" varchar(100) NOT NULL,
  "extended_key" varchar(100) NOT NULL,
  "common_name" varchar(100) NOT NULL,
  "subject_alternative_name" varchar(100)[] NOT NULL,
  "expiration_date" timestamptz NOT NULL DEFAULT (now()),
  "issued_date" timestamptz NOT NULL DEFAULT (now()),
  "revoked" boolean NOT NULL DEFAULT false,
  "revoked_by" varchar(100),
  "revoke_date" timestamptz,
  "certificate_authority_arn" varchar(100)
);

CREATE TABLE "aws_attestation" (
  "client_id" uuid UNIQUE PRIMARY KEY,
  "role_arn" varchar(100),
  "assume_role" varchar(100),
  "security_group_id" varchar(100)[],
  "region" varchar(100),
  "instance_id" varchar(100),
  "image_id" varchar(100),
  "instance_tags" json
);

CREATE TABLE "provisioners" (
  "client_id" uuid UNIQUE PRIMARY KEY,
  "api_token" varchar(100) NOT NULL,
  "provisioner_account" varchar(100) NOT NULL,
  "environments" varchar(100)[] NOT NULL,
  "team" varchar(100) NOT NULL,
  "email" varchar(100) NOT NULL,
  "regular_expression" varchar(100),
  "valid_subject_alternate_names" varchar(100)[] NOT NULL,
  "extended_keys" varchar(100)[] NOT NULL,
  "max_certificate_validity" smallserial NOT NULL,
  "node_attestation" varchar(100)[],
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "created_by" uuid NOT NULL
);

ALTER TABLE "accounts" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("uuid");
ALTER TABLE "provisioners" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("uuid");