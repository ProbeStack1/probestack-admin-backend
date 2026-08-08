-- Adds Zitadel identity-provider metadata alongside the existing Auth0 fields.
-- Run this against the backend application's active database.
-- Example:
--   mysql --host=<host> --user=<user> --password <database> < 2026_07_26_add_zitadel_identity_fields.sql

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'organizations'
    AND COLUMN_NAME = 'zitadel_org_id'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `organizations` ADD COLUMN `zitadel_org_id` varchar(100) DEFAULT NULL AFTER `auth0_org_id`',
  'SELECT 1'
);
PREPARE col_stmt FROM @col_sql;
EXECUTE col_stmt;
DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'zitadel_user_id'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `users` ADD COLUMN `zitadel_user_id` varchar(255) DEFAULT NULL AFTER `auth0_user_id`',
  'SELECT 1'
);
PREPARE col_stmt FROM @col_sql;
EXECUTE col_stmt;
DEALLOCATE PREPARE col_stmt;

SET @table_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'zitadel_login_records'
);
SET @table_sql = IF(
  @table_exists = 0,
  'CREATE TABLE `zitadel_login_records` (
    `id` varchar(36) NOT NULL,
    `email` varchar(255) NOT NULL,
    `organization_id` varchar(36) NOT NULL,
    `organization_name` varchar(255) DEFAULT NULL,
    `external_org_id` varchar(100) DEFAULT NULL,
    `zitadel_org_id` varchar(100) DEFAULT NULL,
    `zitadel_user_id` varchar(255) DEFAULT NULL,
    `name` varchar(255) DEFAULT NULL,
    `picture` text,
    `access_token` text,
    `id_token` text,
    `token_type` varchar(50) DEFAULT NULL,
    `expires_in` int DEFAULT NULL,
    `expires_at` datetime DEFAULT NULL,
    `login_at` datetime DEFAULT NULL,
    `ip_address` varchar(50) DEFAULT NULL,
    `user_agent` text,
    PRIMARY KEY (`id`),
    KEY `idx_zitadel_login_records_org` (`organization_id`),
    KEY `idx_zitadel_login_records_email` (`email`),
    KEY `idx_zitadel_login_records_login_at` (`login_at`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci',
  'SELECT 1'
);
PREPARE table_stmt FROM @table_sql;
EXECUTE table_stmt;
DEALLOCATE PREPARE table_stmt;

SELECT
  TABLE_NAME,
  COLUMN_NAME,
  COLUMN_TYPE,
  IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND (
    (TABLE_NAME = 'organizations' AND COLUMN_NAME = 'zitadel_org_id')
    OR (TABLE_NAME = 'users' AND COLUMN_NAME = 'zitadel_user_id')
    OR (TABLE_NAME = 'zitadel_login_records' AND COLUMN_NAME IN ('id', 'email', 'zitadel_org_id', 'zitadel_user_id'))
  )
ORDER BY TABLE_NAME, ORDINAL_POSITION;
