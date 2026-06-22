"""Peewee migrations -- 033_add_oauth_fields.py."""

import peewee as pw

SQL = pw.SQL


def migrate(migrator, database, fake=False, **kwargs):
    migrator.sql(
        'ALTER TABLE "user" ADD COLUMN "oauth_provider" VARCHAR(20) NULL DEFAULT NULL'
    )
    migrator.sql(
        'ALTER TABLE "user" ADD COLUMN "oauth_sub" VARCHAR(255) NULL DEFAULT NULL'
    )
    migrator.sql(
        'CREATE UNIQUE INDEX IF NOT EXISTS "idx_user_oauth_sub" ON "user" ("oauth_provider", "oauth_sub") '
        'WHERE "oauth_sub" IS NOT NULL'
    )


def rollback(migrator, database, fake=False, **kwargs):
    migrator.sql('DROP INDEX IF EXISTS "idx_user_oauth_sub"')
    migrator.sql('ALTER TABLE "user" DROP COLUMN "oauth_sub"')
    migrator.sql('ALTER TABLE "user" DROP COLUMN "oauth_provider"')
