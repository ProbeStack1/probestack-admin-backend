-- Adds project/APM assignment metadata expected by deployed backend builds.
-- Run this against the backend application's active database.

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'assigned_project_ids'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `users` ADD COLUMN `assigned_project_ids` text DEFAULT NULL AFTER `first_login_token`',
  'SELECT 1'
);
PREPARE col_stmt FROM @col_sql;
EXECUTE col_stmt;
DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'assigned_apm_numbers'
);
SET @col_sql = IF(
  @col_exists = 0,
  'ALTER TABLE `users` ADD COLUMN `assigned_apm_numbers` text DEFAULT NULL AFTER `assigned_project_ids`',
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
  AND TABLE_NAME = 'users'
  AND COLUMN_NAME IN ('assigned_project_ids', 'assigned_apm_numbers')
ORDER BY ORDINAL_POSITION;
