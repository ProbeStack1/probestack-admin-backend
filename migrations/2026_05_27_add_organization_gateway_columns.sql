-- Adds ForgeSphere gateway onboarding metadata expected by server.py.
-- Run this against the backend application's active database.
-- Example:
--   mysql --host=<host> --user=<user> --password <database> < 2026_05_27_add_organization_gateway_columns.sql

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'organizations'
    AND COLUMN_NAME = 'gateway_region'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `organizations` ADD COLUMN `gateway_region` varchar(100) DEFAULT NULL AFTER `auth0_org_id`',
  'SELECT 1'
);
PREPARE col_stmt FROM @col_sql;
EXECUTE col_stmt;
DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'organizations'
    AND COLUMN_NAME = 'gateway_organization_name'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `organizations` ADD COLUMN `gateway_organization_name` varchar(255) DEFAULT NULL AFTER `gateway_region`',
  'SELECT 1'
);
PREPARE col_stmt FROM @col_sql;
EXECUTE col_stmt;
DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'organizations'
    AND COLUMN_NAME = 'gateway_environment_type'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `organizations` ADD COLUMN `gateway_environment_type` varchar(50) DEFAULT NULL AFTER `gateway_organization_name`',
  'SELECT 1'
);
PREPARE col_stmt FROM @col_sql;
EXECUTE col_stmt;
DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'organizations'
    AND COLUMN_NAME = 'gateway_environments'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `organizations` ADD COLUMN `gateway_environments` text DEFAULT NULL AFTER `gateway_environment_type`',
  'SELECT 1'
);
PREPARE col_stmt FROM @col_sql;
EXECUTE col_stmt;
DEALLOCATE PREPARE col_stmt;

SELECT
  COLUMN_NAME,
  COLUMN_TYPE,
  IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'organizations'
  AND COLUMN_NAME IN (
    'gateway_region',
    'gateway_organization_name',
    'gateway_environment_type',
    'gateway_environments'
  )
ORDER BY ORDINAL_POSITION;
