-- Reset recent catalog/subscription/request tables while preserving Auth0-bound
-- organization and user identity rows.
--
-- Preserved:
--   organizations, users, admins, roles, auth0_login_records, business_units,
--   projects, project_team_members, notifications, individual_user_requests.
--
-- Rebuilt:
--   products, plans, plan_tools, subscriptions, subscription_tools, billing,
--   plan_upgrade_requests and normalized request item/tool tables,
--   organization_subscription_requests and normalized request item/tool tables,
--   user_requests.
--
-- This script intentionally replaces non-live subscription/catalog data.
-- Take a database backup before running.

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `billing`;
DROP TABLE IF EXISTS `subscription_tools`;
DROP TABLE IF EXISTS `organization_subscription_request_tools`;
DROP TABLE IF EXISTS `organization_subscription_request_items`;
DROP TABLE IF EXISTS `organization_subscription_requests`;
DROP TABLE IF EXISTS `plan_upgrade_request_tools`;
DROP TABLE IF EXISTS `plan_upgrade_request_items`;
DROP TABLE IF EXISTS `plan_upgrade_requests`;
DROP TABLE IF EXISTS `user_requests`;
DROP TABLE IF EXISTS `plan_tools`;
DROP TABLE IF EXISTS `subscriptions`;
DROP TABLE IF EXISTS `plans`;
DROP TABLE IF EXISTS `products`;

SET FOREIGN_KEY_CHECKS = 1;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'organizations' AND COLUMN_NAME = 'gateway_region'
);
SET @col_sql = IF(@col_exists = 0, 'ALTER TABLE `organizations` ADD COLUMN `gateway_region` varchar(100) DEFAULT NULL AFTER `auth0_org_id`', 'SELECT 1');
PREPARE col_stmt FROM @col_sql; EXECUTE col_stmt; DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'organizations' AND COLUMN_NAME = 'gateway_organization_name'
);
SET @col_sql = IF(@col_exists = 0, 'ALTER TABLE `organizations` ADD COLUMN `gateway_organization_name` varchar(255) DEFAULT NULL AFTER `gateway_region`', 'SELECT 1');
PREPARE col_stmt FROM @col_sql; EXECUTE col_stmt; DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'organizations' AND COLUMN_NAME = 'gateway_environment_type'
);
SET @col_sql = IF(@col_exists = 0, 'ALTER TABLE `organizations` ADD COLUMN `gateway_environment_type` varchar(50) DEFAULT NULL AFTER `gateway_organization_name`', 'SELECT 1');
PREPARE col_stmt FROM @col_sql; EXECUTE col_stmt; DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'organizations' AND COLUMN_NAME = 'gateway_environments'
);
SET @col_sql = IF(@col_exists = 0, 'ALTER TABLE `organizations` ADD COLUMN `gateway_environments` text DEFAULT NULL AFTER `gateway_environment_type`', 'SELECT 1');
PREPARE col_stmt FROM @col_sql; EXECUTE col_stmt; DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'assigned_project_ids'
);
SET @col_sql = IF(@col_exists = 0, 'ALTER TABLE `users` ADD COLUMN `assigned_project_ids` text DEFAULT NULL AFTER `first_login_token`', 'SELECT 1');
PREPARE col_stmt FROM @col_sql; EXECUTE col_stmt; DEALLOCATE PREPARE col_stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'assigned_apm_numbers'
);
SET @col_sql = IF(@col_exists = 0, 'ALTER TABLE `users` ADD COLUMN `assigned_apm_numbers` text DEFAULT NULL AFTER `assigned_project_ids`', 'SELECT 1');
PREPARE col_stmt FROM @col_sql; EXECUTE col_stmt; DEALLOCATE PREPARE col_stmt;

CREATE TABLE `products` (
  `id` varchar(36) NOT NULL,
  `key` varchar(100) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text,
  `display_order` int NOT NULL DEFAULT '0',
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_products_key` (`key`),
  KEY `idx_products_display_order` (`display_order`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `plans` (
  `id` varchar(36) NOT NULL,
  `name` varchar(255) NOT NULL,
  `product_id` varchar(36) DEFAULT NULL,
  `tool` varchar(100) NOT NULL,
  `description` text NOT NULL,
  `features` text NOT NULL,
  `price_monthly` float NOT NULL DEFAULT '0',
  `price_yearly` float NOT NULL DEFAULT '0',
  `price_label` varchar(100) DEFAULT NULL,
  `billing_period` varchar(100) DEFAULT NULL,
  `api_limit` int NOT NULL DEFAULT '0',
  `cost` float NOT NULL DEFAULT '0',
  `is_popular` tinyint(1) NOT NULL DEFAULT '0',
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_plans_product_id` (`product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `plan_tools` (
  `id` varchar(36) NOT NULL,
  `plan_id` varchar(36) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text,
  `price_monthly` float NOT NULL DEFAULT '0',
  `price_yearly` float NOT NULL DEFAULT '0',
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `display_order` int NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_plan_tools_plan` (`plan_id`),
  CONSTRAINT `plan_tools_ibfk_1` FOREIGN KEY (`plan_id`) REFERENCES `plans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `subscriptions` (
  `id` varchar(36) NOT NULL,
  `organization_id` varchar(36) NOT NULL,
  `organization_name` varchar(255) DEFAULT NULL,
  `plan_id` varchar(100) NOT NULL,
  `plan_name` varchar(255) DEFAULT NULL,
  `tools` text NOT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'active',
  `start_date` datetime NOT NULL,
  `end_date` datetime NOT NULL,
  `billing_cycle` varchar(50) NOT NULL DEFAULT 'monthly',
  `amount` float NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_subscriptions_org` (`organization_id`),
  CONSTRAINT `subscriptions_ibfk_1` FOREIGN KEY (`organization_id`) REFERENCES `organizations` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `subscription_tools` (
  `id` varchar(36) NOT NULL,
  `subscription_id` varchar(36) NOT NULL,
  `plan_tool_id` varchar(36) NOT NULL,
  `tool_key` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_subscription_tools_plan_tool` (`subscription_id`,`plan_tool_id`),
  UNIQUE KEY `uq_subscription_tools_tool_key` (`subscription_id`,`tool_key`),
  KEY `idx_subscription_tools_plan_tool` (`plan_tool_id`),
  CONSTRAINT `subscription_tools_ibfk_1` FOREIGN KEY (`subscription_id`) REFERENCES `subscriptions` (`id`) ON DELETE CASCADE,
  CONSTRAINT `subscription_tools_ibfk_2` FOREIGN KEY (`plan_tool_id`) REFERENCES `plan_tools` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `billing` (
  `id` varchar(36) NOT NULL,
  `organization_id` varchar(36) NOT NULL,
  `organization_name` varchar(255) DEFAULT NULL,
  `subscription_id` varchar(36) NOT NULL,
  `amount` float NOT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'pending',
  `invoice_number` varchar(100) NOT NULL,
  `billing_date` datetime NOT NULL,
  `due_date` datetime NOT NULL,
  `paid_date` datetime DEFAULT NULL,
  `payment_method` varchar(100) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `organization_id` (`organization_id`),
  KEY `subscription_id` (`subscription_id`),
  CONSTRAINT `billing_ibfk_1` FOREIGN KEY (`organization_id`) REFERENCES `organizations` (`id`),
  CONSTRAINT `billing_ibfk_2` FOREIGN KEY (`subscription_id`) REFERENCES `subscriptions` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `plan_upgrade_requests` (
  `id` varchar(36) NOT NULL,
  `organization_id` varchar(36) NOT NULL,
  `organization_name` varchar(255) DEFAULT NULL,
  `current_plan_id` varchar(100) NOT NULL,
  `current_plan_name` varchar(255) DEFAULT NULL,
  `requested_plan_id` varchar(100) DEFAULT NULL,
  `requested_plan_name` varchar(255) DEFAULT NULL,
  `requested_tools` text NOT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'pending',
  `reason` text,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `approved_at` datetime DEFAULT NULL,
  `rejected_at` datetime DEFAULT NULL,
  `rejection_reason` text,
  `requested_by` varchar(36) NOT NULL,
  `requested_plan_ids` text,
  `requested_plans_details` text,
  PRIMARY KEY (`id`),
  KEY `idx_plan_upgrade_org` (`organization_id`),
  KEY `idx_plan_upgrade_status` (`status`),
  CONSTRAINT `plan_upgrade_requests_ibfk_1` FOREIGN KEY (`organization_id`) REFERENCES `organizations` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `plan_upgrade_request_items` (
  `id` varchar(36) NOT NULL,
  `request_id` varchar(36) NOT NULL,
  `plan_id` varchar(36) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_upgrade_request_items_request_plan` (`request_id`,`plan_id`),
  KEY `plan_id` (`plan_id`),
  CONSTRAINT `plan_upgrade_request_items_ibfk_1` FOREIGN KEY (`request_id`) REFERENCES `plan_upgrade_requests` (`id`) ON DELETE CASCADE,
  CONSTRAINT `plan_upgrade_request_items_ibfk_2` FOREIGN KEY (`plan_id`) REFERENCES `plans` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `plan_upgrade_request_tools` (
  `id` varchar(36) NOT NULL,
  `request_item_id` varchar(36) NOT NULL,
  `plan_tool_id` varchar(36) NOT NULL,
  `tool_key` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_upgrade_request_tools_plan_tool` (`request_item_id`,`plan_tool_id`),
  UNIQUE KEY `uq_upgrade_request_tools_tool_key` (`request_item_id`,`tool_key`),
  KEY `plan_tool_id` (`plan_tool_id`),
  CONSTRAINT `plan_upgrade_request_tools_ibfk_1` FOREIGN KEY (`request_item_id`) REFERENCES `plan_upgrade_request_items` (`id`) ON DELETE CASCADE,
  CONSTRAINT `plan_upgrade_request_tools_ibfk_2` FOREIGN KEY (`plan_tool_id`) REFERENCES `plan_tools` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `organization_subscription_requests` (
  `id` varchar(36) NOT NULL,
  `organization_id` varchar(36) NOT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'pending',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `approved_at` datetime DEFAULT NULL,
  `rejected_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `organization_id` (`organization_id`),
  CONSTRAINT `organization_subscription_requests_ibfk_1` FOREIGN KEY (`organization_id`) REFERENCES `organizations` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `organization_subscription_request_items` (
  `id` varchar(36) NOT NULL,
  `request_id` varchar(36) NOT NULL,
  `plan_id` varchar(36) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_org_subscription_request_items_request_plan` (`request_id`,`plan_id`),
  KEY `plan_id` (`plan_id`),
  CONSTRAINT `organization_subscription_request_items_ibfk_1` FOREIGN KEY (`request_id`) REFERENCES `organization_subscription_requests` (`id`) ON DELETE CASCADE,
  CONSTRAINT `organization_subscription_request_items_ibfk_2` FOREIGN KEY (`plan_id`) REFERENCES `plans` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `organization_subscription_request_tools` (
  `id` varchar(36) NOT NULL,
  `request_item_id` varchar(36) NOT NULL,
  `plan_tool_id` varchar(36) NOT NULL,
  `tool_key` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_org_subscription_request_tools_plan_tool` (`request_item_id`,`plan_tool_id`),
  UNIQUE KEY `uq_org_subscription_request_tools_tool_key` (`request_item_id`,`tool_key`),
  KEY `plan_tool_id` (`plan_tool_id`),
  CONSTRAINT `organization_subscription_request_tools_ibfk_1` FOREIGN KEY (`request_item_id`) REFERENCES `organization_subscription_request_items` (`id`) ON DELETE CASCADE,
  CONSTRAINT `organization_subscription_request_tools_ibfk_2` FOREIGN KEY (`plan_tool_id`) REFERENCES `plan_tools` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `user_requests` (
  `id` varchar(36) NOT NULL,
  `email` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `organization_id` varchar(36) NOT NULL,
  `organization_name` varchar(255) DEFAULT NULL,
  `requested_role` varchar(100) NOT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'pending',
  `job_title` varchar(255) DEFAULT NULL,
  `department` varchar(255) DEFAULT NULL,
  `phone` varchar(50) DEFAULT NULL,
  `notes` text,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `approved_at` datetime DEFAULT NULL,
  `rejected_at` datetime DEFAULT NULL,
  `rejection_reason` text,
  `approved_role_id` varchar(36) DEFAULT NULL,
  `approved_business_unit_id` varchar(36) DEFAULT NULL,
  `approved_project_id` varchar(36) DEFAULT NULL,
  `approved_project_role` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_user_requests_email` (`email`),
  KEY `idx_user_requests_org` (`organization_id`),
  KEY `idx_user_requests_status` (`status`),
  CONSTRAINT `user_requests_ibfk_1` FOREIGN KEY (`organization_id`) REFERENCES `organizations` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO `products` (`id`,`key`,`name`,`description`,`display_order`,`is_active`)
VALUES
  ('prod_forgeshift','forgeshift','ForgeShift - Gateway Migration','Automated migration and transformation of API proxies across disparate gateway environments.',10,1),
  ('prod_forgestudio','forgestudio','ForgeStudio - API Design','Powerful API design and development studio for modern collaborative teams.',20,1),
  ('prod_forgeq','forgeq','ForgeQ - API, MCP & AI Testing','Automated API, MCP & AI testing, SDK, quality assurance, and mock server generation playground.',30,1),
  ('prod_forgesphere','forgesphere','ForgeSphere - API Development Lifecycle','Centralized API Lifecycle generation, observability, logging, and comprehensive analytics for your API ecosystem.',40,1),
  ('prod_forgeai','forgeai','ForgeAi - AI Gateway','AI Gateway to monitor, secure, and route your LLM & AI provider traffic seamlessly.',50,1),
  ('prod_agentic_ai','agentic_ai','Agentic AI Platform','End-to-end intelligent agent workflow orchestration and autonomous task execution.',60,1);

INSERT INTO `plans`
  (`id`,`name`,`product_id`,`tool`,`description`,`features`,`price_monthly`,`price_yearly`,`price_label`,`billing_period`,`api_limit`,`cost`,`is_popular`,`is_active`)
VALUES
  ('plan_forgeshift_starter','Starter','prod_forgeshift','forgeshift','Basic migration tools for small teams.','["Up to 10 migrations","Basic UI access","Email support"]',0,0,'$0','/mo',0,0,0,1),
  ('plan_forgeshift_enterprise_plus','Enterprise - Plus','prod_forgeshift','forgeshift','Comprehensive migration support.','["Zero-downtime migration","Unlimited proxy migration","Dedicated migration team","8x5 support"]',0,0,'Contact Sales',NULL,0,0,0,1),
  ('plan_forgestudio_starter','Starter','prod_forgestudio','forgestudio','Ideal for small API teams.','["1 user","2 public APIs","1 project","Community support"]',0,0,'$0','/month/user',0,0,0,1),
  ('plan_forgestudio_enterprise','Enterprise','prod_forgestudio','forgestudio','Advanced collaboration.','["Private APIs","Multi-user editing","Versioning","Team access with 5 users"]',40,40,'$40','/month/user',0,40,1,1),
  ('plan_forgestudio_enterprise_plus','Enterprise - Plus','prod_forgestudio','forgestudio','Dedicated Enterprise for scale.','["Unlimited users","SSO","Audit logs","Advanced governance"]',0,0,'Contact Sales',NULL,0,0,0,1),
  ('plan_forgeq_starter','Starter','prod_forgeq','forgeq','Basic testing capabilities.','["Standard API testing","Collections testing","Environment variables","Email support"]',0,0,'$0','/month/user',0,0,0,1),
  ('plan_forgeq_enterprise','Enterprise','prod_forgeq','forgeq','Comprehensive API and MCP testing.','["Mock servers","Git sync","CI/CD integration","Monitoring automation"]',30,30,'$30','/month/user',0,30,1,1),
  ('plan_forgeq_enterprise_plus','Enterprise - Plus','prod_forgeq','forgeq','Advanced API, UI, MCP and AI testing.','["SSO","Audit logs","Unlimited runs","AI debugging"]',0,0,'Contact Sales',NULL,0,0,0,1),
  ('plan_forgesphere_starter','Starter','prod_forgesphere','forgesphere','Basic API Lifecycle.','["Up to 50 services","API generation","Contract testing","Email support"]',50,50,'$50','/month/user',0,50,0,1),
  ('plan_forgesphere_enterprise','Enterprise','prod_forgesphere','forgesphere','Advanced API Lifecycle.','["Versioning","Multi-gateway deployment","API governance","Priority support"]',150,150,'$150','/month/user',0,150,1,1),
  ('plan_forgesphere_enterprise_plus','Enterprise - Plus','prod_forgesphere','forgesphere','Unlimited scaled API Lifecycle.','["MCP lifecycle","Advanced analytics","Enterprise governance","8x5 support"]',0,0,'Contact Sales',NULL,0,0,0,1),
  ('plan_forgeai_starter','Starter','prod_forgeai','forgeai','Advanced AI traffic routing and observability.','["200K API calls per month","Multi-provider routing","Gateway dashboard","Email support"]',3500,3500,'$3,500','/month',0,3500,0,1),
  ('plan_forgeai_enterprise','Enterprise','prod_forgeai','forgeai','Advanced AI traffic routing and observability.','["3M API calls per month","Caching","PII redaction","Priority support"]',9500,9500,'$9,500','/month',0,9500,1,1),
  ('plan_forgeai_enterprise_plus','Enterprise - Plus','prod_forgeai','forgeai','Advanced AI traffic routing and observability.','["Unlimited tokens","Dedicated infrastructure","Private deployment","24x7 support"]',0,0,'Contact Sales',NULL,0,0,0,1),
  ('plan_agentic_ai_starter','Starter','prod_agentic_ai','agentic_ai','Explore autonomous agents.','["Up to 10 autonomous agents","Basic RAG","Email support"]',0,0,'$0','/month/user',0,0,0,1),
  ('plan_agentic_ai_enterprise','Enterprise','prod_agentic_ai','agentic_ai','Scale autonomous agents.','["Team agent workflows","Basic RAG","Email support"]',100,100,'$100','/month/user',0,100,0,1),
  ('plan_agentic_ai_enterprise_plus','Enterprise - Plus','prod_agentic_ai','agentic_ai','Unlimited agentic workflows.','["Unlimited agents","Agent inventory","Multi-model support","24x7 support"]',0,0,'Contact Sales','/ 200 Users',0,0,1,1);

INSERT INTO `plan_tools`
  (`id`,`plan_id`,`name`,`description`,`price_monthly`,`price_yearly`,`is_active`,`display_order`)
SELECT
  CONCAT('pt_', LEFT(REPLACE(`id`, 'plan_', ''), 33)),
  `id`,
  CONCAT(`name`, ' access'),
  `description`,
  0,
  0,
  1,
  0
FROM `plans`;

INSERT INTO `subscriptions`
  (`id`,`organization_id`,`organization_name`,`plan_id`,`plan_name`,`tools`,`status`,`start_date`,`end_date`,`billing_cycle`,`amount`,`created_at`)
SELECT
  CONCAT('sub_', LEFT(REPLACE(o.`id`, '-', ''), 32)) AS `id`,
  o.`id` AS `organization_id`,
  COALESCE(o.`external_org_id`, o.`name`) AS `organization_name`,
  p.`id` AS `plan_id`,
  p.`name` AS `plan_name`,
  JSON_ARRAY(CONCAT(p.`name`, ' access')) AS `tools`,
  'active' AS `status`,
  UTC_TIMESTAMP() AS `start_date`,
  DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 YEAR) AS `end_date`,
  'monthly' AS `billing_cycle`,
  p.`cost` AS `amount`,
  UTC_TIMESTAMP() AS `created_at`
FROM `organizations` o
JOIN `plans` p ON p.`id` = CASE MOD(CRC32(o.`id`), 6)
  WHEN 0 THEN 'plan_forgestudio_enterprise'
  WHEN 1 THEN 'plan_forgeq_enterprise'
  WHEN 2 THEN 'plan_forgesphere_enterprise'
  WHEN 3 THEN 'plan_forgeai_starter'
  WHEN 4 THEN 'plan_agentic_ai_enterprise'
  ELSE 'plan_forgeshift_enterprise_plus'
END
WHERE o.`status` = 'approved';

INSERT INTO `subscription_tools`
  (`id`,`subscription_id`,`plan_tool_id`,`tool_key`,`created_at`)
SELECT
  CONCAT('st_', LEFT(REPLACE(s.`id`, 'sub_', ''), 33)),
  s.`id`,
  pt.`id`,
  NULL,
  UTC_TIMESTAMP()
FROM `subscriptions` s
JOIN `plan_tools` pt ON pt.`plan_id` = s.`plan_id` AND pt.`display_order` = 0;

UPDATE `organizations` o
JOIN `subscriptions` s ON s.`organization_id` = o.`id` AND s.`status` = 'active'
SET
  o.`requested_plan` = s.`plan_id`,
  o.`requested_tools` = s.`tools`,
  o.`updated_at` = UTC_TIMESTAMP()
WHERE o.`status` = 'approved';

INSERT INTO `organization_subscription_requests`
  (`id`,`organization_id`,`status`,`created_at`,`updated_at`,`approved_at`,`rejected_at`)
SELECT
  CONCAT('osr_', LEFT(REPLACE(o.`id`, '-', ''), 32)),
  o.`id`,
  'approved',
  UTC_TIMESTAMP(),
  UTC_TIMESTAMP(),
  UTC_TIMESTAMP(),
  NULL
FROM `organizations` o
WHERE o.`status` = 'approved';

INSERT INTO `organization_subscription_request_items`
  (`id`,`request_id`,`plan_id`,`created_at`)
SELECT
  CONCAT('osri_', LEFT(REPLACE(o.`id`, '-', ''), 31)),
  CONCAT('osr_', LEFT(REPLACE(o.`id`, '-', ''), 32)),
  s.`plan_id`,
  UTC_TIMESTAMP()
FROM `organizations` o
JOIN `subscriptions` s ON s.`organization_id` = o.`id` AND s.`status` = 'active'
WHERE o.`status` = 'approved';

INSERT INTO `organization_subscription_request_tools`
  (`id`,`request_item_id`,`plan_tool_id`,`tool_key`,`created_at`)
SELECT
  CONCAT('osrt_', LEFT(REPLACE(o.`id`, '-', ''), 31)),
  CONCAT('osri_', LEFT(REPLACE(o.`id`, '-', ''), 31)),
  pt.`id`,
  NULL,
  UTC_TIMESTAMP()
FROM `organizations` o
JOIN `subscriptions` s ON s.`organization_id` = o.`id` AND s.`status` = 'active'
JOIN `plan_tools` pt ON pt.`plan_id` = s.`plan_id` AND pt.`display_order` = 0
WHERE o.`status` = 'approved';

SELECT
  o.`id` AS `organization_id`,
  COALESCE(o.`external_org_id`, o.`name`) AS `organization_name`,
  s.`plan_id`,
  s.`plan_name`,
  s.`amount`,
  s.`status`
FROM `organizations` o
LEFT JOIN `subscriptions` s ON s.`organization_id` = o.`id` AND s.`status` = 'active'
WHERE o.`status` = 'approved'
ORDER BY o.`created_at`, o.`id`;
