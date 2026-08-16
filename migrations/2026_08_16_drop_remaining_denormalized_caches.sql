-- Drop remaining denormalized cache columns after backfilling normalized tables.
-- Display values now come from organizations, roles, plans, and request/tool join tables.

-- Backfill subscription_tools from subscriptions.tools where the selected tool can be resolved.
SET @backfill_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'subscriptions'
        AND COLUMN_NAME = 'tools'
    ),
    "INSERT IGNORE INTO `subscription_tools` (`id`, `subscription_id`, `plan_tool_id`, `tool_key`, `created_at`)
     SELECT UUID(), s.`id`, pt.`id`, NULL, UTC_TIMESTAMP()
     FROM `subscriptions` s
     JOIN JSON_TABLE(
       IF(JSON_VALID(COALESCE(s.`tools`, '')), CAST(s.`tools` AS JSON), JSON_ARRAY()),
       '$[*]' COLUMNS (`tool_key` VARCHAR(255) PATH '$')
     ) jt
     JOIN `plan_tools` pt
       ON pt.`plan_id` = s.`plan_id`
      AND (pt.`id` = jt.`tool_key` OR pt.`name` = jt.`tool_key`)",
    "SELECT 1"
  )
);
PREPARE stmt FROM @backfill_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Backfill organization subscription requests from organizations.requested_plan/requested_tools.
SET @backfill_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'organizations'
        AND COLUMN_NAME = 'requested_plan'
    ),
    "INSERT INTO `organization_subscription_requests`
       (`id`, `organization_id`, `status`, `created_at`, `updated_at`, `approved_at`, `rejected_at`)
     SELECT UUID(), o.`id`, o.`status`, COALESCE(o.`created_at`, UTC_TIMESTAMP()), COALESCE(o.`updated_at`, UTC_TIMESTAMP()), o.`approved_at`, o.`rejected_at`
     FROM `organizations` o
     WHERE NOT EXISTS (
       SELECT 1 FROM `organization_subscription_requests` r
       WHERE r.`organization_id` = o.`id`
     )
       AND o.`requested_plan` IS NOT NULL
       AND o.`requested_plan` <> ''",
    "SELECT 1"
  )
);
PREPARE stmt FROM @backfill_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @backfill_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'organizations'
        AND COLUMN_NAME = 'requested_plan'
    ),
    "INSERT IGNORE INTO `organization_subscription_request_items` (`id`, `request_id`, `plan_id`, `created_at`)
     SELECT UUID(), r.`id`, jt.`plan_id`, COALESCE(o.`created_at`, UTC_TIMESTAMP())
     FROM `organizations` o
     JOIN (
       SELECT r1.*
       FROM `organization_subscription_requests` r1
       JOIN (
         SELECT `organization_id`, MAX(`created_at`) AS `created_at`
         FROM `organization_subscription_requests`
         GROUP BY `organization_id`
       ) latest
         ON latest.`organization_id` = r1.`organization_id`
        AND latest.`created_at` = r1.`created_at`
     ) r ON r.`organization_id` = o.`id`
     JOIN JSON_TABLE(
       IF(JSON_VALID(COALESCE(o.`requested_plan`, '')), CAST(o.`requested_plan` AS JSON), JSON_ARRAY(o.`requested_plan`)),
       '$[*]' COLUMNS (`plan_id` VARCHAR(100) PATH '$')
     ) jt
     WHERE jt.`plan_id` IS NOT NULL AND jt.`plan_id` <> ''",
    "SELECT 1"
  )
);
PREPARE stmt FROM @backfill_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @backfill_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'organizations'
        AND COLUMN_NAME = 'requested_tools'
    ),
    "INSERT IGNORE INTO `organization_subscription_request_tools` (`id`, `request_item_id`, `plan_tool_id`, `tool_key`, `created_at`)
     SELECT UUID(), i.`id`, pt.`id`, NULL, UTC_TIMESTAMP()
     FROM `organizations` o
     JOIN `organization_subscription_requests` r ON r.`organization_id` = o.`id`
     JOIN `organization_subscription_request_items` i ON i.`request_id` = r.`id`
     JOIN JSON_TABLE(
       IF(JSON_VALID(COALESCE(o.`requested_tools`, '')), CAST(o.`requested_tools` AS JSON), JSON_ARRAY()),
       '$[*]' COLUMNS (`tool_key` VARCHAR(255) PATH '$')
     ) jt
     JOIN `plan_tools` pt
       ON pt.`plan_id` = i.`plan_id`
      AND (pt.`id` = jt.`tool_key` OR pt.`name` = jt.`tool_key`)",
    "SELECT 1"
  )
);
PREPARE stmt FROM @backfill_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Backfill plan upgrade request items/tools from old request cache columns.
SET @backfill_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'plan_upgrade_requests'
        AND COLUMN_NAME = 'requested_plan_ids'
    ),
    "INSERT IGNORE INTO `plan_upgrade_request_items` (`id`, `request_id`, `plan_id`, `created_at`)
     SELECT UUID(), r.`id`, jt.`plan_id`, COALESCE(r.`created_at`, UTC_TIMESTAMP())
     FROM `plan_upgrade_requests` r
     JOIN JSON_TABLE(
       IF(JSON_VALID(COALESCE(r.`requested_plan_ids`, '')), CAST(r.`requested_plan_ids` AS JSON), JSON_ARRAY(r.`requested_plan_id`)),
       '$[*]' COLUMNS (`plan_id` VARCHAR(100) PATH '$')
     ) jt
     WHERE jt.`plan_id` IS NOT NULL AND jt.`plan_id` <> ''",
    "SELECT 1"
  )
);
PREPARE stmt FROM @backfill_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @backfill_sql := (
  SELECT IF(
    EXISTS (
      SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'plan_upgrade_requests'
        AND COLUMN_NAME = 'requested_tools'
    ),
    "INSERT IGNORE INTO `plan_upgrade_request_tools` (`id`, `request_item_id`, `plan_tool_id`, `tool_key`, `created_at`)
     SELECT UUID(), i.`id`, pt.`id`, NULL, UTC_TIMESTAMP()
     FROM `plan_upgrade_requests` r
     JOIN `plan_upgrade_request_items` i ON i.`request_id` = r.`id`
     JOIN JSON_TABLE(
       IF(JSON_VALID(COALESCE(r.`requested_tools`, '')), CAST(r.`requested_tools` AS JSON), JSON_ARRAY()),
       '$[*]' COLUMNS (`tool_key` VARCHAR(255) PATH '$')
     ) jt
     JOIN `plan_tools` pt
       ON pt.`plan_id` = i.`plan_id`
      AND (pt.`id` = jt.`tool_key` OR pt.`name` = jt.`tool_key`)",
    "SELECT 1"
  )
);
PREPARE stmt FROM @backfill_sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Drop cache columns.
SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'organizations' AND COLUMN_NAME = 'requested_plan'), 'ALTER TABLE `organizations` DROP COLUMN `requested_plan`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'organizations' AND COLUMN_NAME = 'requested_tools'), 'ALTER TABLE `organizations` DROP COLUMN `requested_tools`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'subscriptions' AND COLUMN_NAME = 'plan_name'), 'ALTER TABLE `subscriptions` DROP COLUMN `plan_name`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'subscriptions' AND COLUMN_NAME = 'tools'), 'ALTER TABLE `subscriptions` DROP COLUMN `tools`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'role_name'), 'ALTER TABLE `users` DROP COLUMN `role_name`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plan_upgrade_requests' AND COLUMN_NAME = 'current_plan_name'), 'ALTER TABLE `plan_upgrade_requests` DROP COLUMN `current_plan_name`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plan_upgrade_requests' AND COLUMN_NAME = 'requested_plan_id'), 'ALTER TABLE `plan_upgrade_requests` DROP COLUMN `requested_plan_id`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plan_upgrade_requests' AND COLUMN_NAME = 'requested_plan_name'), 'ALTER TABLE `plan_upgrade_requests` DROP COLUMN `requested_plan_name`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plan_upgrade_requests' AND COLUMN_NAME = 'requested_plan_ids'), 'ALTER TABLE `plan_upgrade_requests` DROP COLUMN `requested_plan_ids`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plan_upgrade_requests' AND COLUMN_NAME = 'requested_plans_details'), 'ALTER TABLE `plan_upgrade_requests` DROP COLUMN `requested_plans_details`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plan_upgrade_requests' AND COLUMN_NAME = 'requested_tools'), 'ALTER TABLE `plan_upgrade_requests` DROP COLUMN `requested_tools`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plan_tools' AND COLUMN_NAME = 'price_monthly'), 'ALTER TABLE `plan_tools` DROP COLUMN `price_monthly`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @drop_col_sql := (
  SELECT IF(EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plan_tools' AND COLUMN_NAME = 'price_yearly'), 'ALTER TABLE `plan_tools` DROP COLUMN `price_yearly`', 'SELECT 1')
);
PREPARE stmt FROM @drop_col_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
