-- Adds optional custom domains for the main app and product subscriptions.
-- Run this against the backend application's active database.

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'organizations'
    AND COLUMN_NAME = 'main_app_domain'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `organizations` ADD COLUMN `main_app_domain` varchar(255) DEFAULT NULL AFTER `domain`',
  'SELECT 1'
);
PREPARE col_stmt FROM @col_sql;
EXECUTE col_stmt;
DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'subscriptions'
    AND COLUMN_NAME = 'custom_domain'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `subscriptions` ADD COLUMN `custom_domain` varchar(255) DEFAULT NULL AFTER `used_quota`',
  'SELECT 1'
);
PREPARE col_stmt FROM @col_sql;
EXECUTE col_stmt;
DEALLOCATE PREPARE col_stmt;

SELECT
  TABLE_NAME,
  COLUMN_NAME,
  COLUMN_TYPE,
  IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND (
    (TABLE_NAME = 'organizations' AND COLUMN_NAME = 'main_app_domain')
    OR (TABLE_NAME = 'subscriptions' AND COLUMN_NAME = 'custom_domain')
  )
ORDER BY TABLE_NAME, ORDINAL_POSITION;
