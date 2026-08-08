-- Add refresh token storage for Zitadel login records.
-- Usage:
--   mysql --host=<host> --user=<user> --password <database> < 2026_07_30_add_zitadel_refresh_token.sql

SET @database_name = DATABASE();

SET @add_refresh_token_sql = (
  SELECT IF(
    COUNT(*) = 0,
    'ALTER TABLE `zitadel_login_records` ADD COLUMN `refresh_token` text DEFAULT NULL AFTER `access_token`',
    'SELECT ''refresh_token already exists on zitadel_login_records'' AS message'
  )
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @database_name
    AND TABLE_NAME = 'zitadel_login_records'
    AND COLUMN_NAME = 'refresh_token'
);

PREPARE stmt FROM @add_refresh_token_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT
  TABLE_NAME,
  COLUMN_NAME,
  DATA_TYPE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = @database_name
  AND TABLE_NAME = 'zitadel_login_records'
  AND COLUMN_NAME = 'refresh_token';
