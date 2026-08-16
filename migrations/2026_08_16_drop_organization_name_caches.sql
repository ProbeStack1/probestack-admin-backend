-- Drop deprecated organization_name cache columns from child tables.
-- Organization display names are resolved from organizations.id -> organizations.name.

SET @drop_col_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'admins'
        AND COLUMN_NAME = 'organization_name'
    ),
    'ALTER TABLE `admins` DROP COLUMN `organization_name`',
    'SELECT 1'
  )
);
PREPARE stmt FROM @drop_col_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'subscriptions'
        AND COLUMN_NAME = 'organization_name'
    ),
    'ALTER TABLE `subscriptions` DROP COLUMN `organization_name`',
    'SELECT 1'
  )
);
PREPARE stmt FROM @drop_col_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'users'
        AND COLUMN_NAME = 'organization_name'
    ),
    'ALTER TABLE `users` DROP COLUMN `organization_name`',
    'SELECT 1'
  )
);
PREPARE stmt FROM @drop_col_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'billing'
        AND COLUMN_NAME = 'organization_name'
    ),
    'ALTER TABLE `billing` DROP COLUMN `organization_name`',
    'SELECT 1'
  )
);
PREPARE stmt FROM @drop_col_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'user_requests'
        AND COLUMN_NAME = 'organization_name'
    ),
    'ALTER TABLE `user_requests` DROP COLUMN `organization_name`',
    'SELECT 1'
  )
);
PREPARE stmt FROM @drop_col_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'plan_upgrade_requests'
        AND COLUMN_NAME = 'organization_name'
    ),
    'ALTER TABLE `plan_upgrade_requests` DROP COLUMN `organization_name`',
    'SELECT 1'
  )
);
PREPARE stmt FROM @drop_col_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'auth0_login_records'
        AND COLUMN_NAME = 'organization_name'
    ),
    'ALTER TABLE `auth0_login_records` DROP COLUMN `organization_name`',
    'SELECT 1'
  )
);
PREPARE stmt FROM @drop_col_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'zitadel_login_records'
        AND COLUMN_NAME = 'organization_name'
    ),
    'ALTER TABLE `zitadel_login_records` DROP COLUMN `organization_name`',
    'SELECT 1'
  )
);
PREPARE stmt FROM @drop_col_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
