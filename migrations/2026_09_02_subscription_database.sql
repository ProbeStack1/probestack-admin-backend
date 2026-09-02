-- Adds optional per-product database name on subscriptions.

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'subscriptions'
    AND COLUMN_NAME = 'database'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `subscriptions` ADD COLUMN `database` varchar(255) DEFAULT NULL AFTER `custom_domain`',
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
  AND TABLE_NAME = 'subscriptions'
  AND COLUMN_NAME = 'database';
