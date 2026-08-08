-- Adds per-organization-plan API capacity on subscriptions.

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'subscriptions'
    AND COLUMN_NAME = 'api_count'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `subscriptions` ADD COLUMN `api_count` int DEFAULT NULL',
  'SELECT 1'
);
PREPARE col_stmt FROM @col_sql;
EXECUTE col_stmt;
DEALLOCATE PREPARE col_stmt;
