-- ProbeStack Cloud SQL migration for standardized roles and current product/plan catalog.
--
-- Safe intent:
--   - Does NOT delete users, admins, organizations, subscriptions, user_requests, or custom products/plans.
--   - Adds missing schema pieces needed by the current backend.
--   - Upserts the standard global role catalog.
--   - Remaps users/user_requests to standard global roles without deleting the user records.
--   - Upserts the official products, plans, and default selectable plan tools.
--
-- Recommended before running:
--   mysqldump --single-transaction --routines --triggers <db_name> > backup_before_2026_07_21.sql

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- Schema compatibility helpers
-- ---------------------------------------------------------------------------

-- Cloud SQL Studio does not support the mysql client's DELIMITER command, so
-- this script uses prepared statements instead of a stored procedure.

-- Roles must support global roles with organization_id = NULL.
ALTER TABLE `roles` MODIFY COLUMN `organization_id` varchar(36) DEFAULT NULL;

CREATE TABLE IF NOT EXISTS `products` (
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

CREATE TABLE IF NOT EXISTS `plans` (
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

CREATE TABLE IF NOT EXISTS `plan_tools` (
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
  KEY `idx_plan_tools_plan` (`plan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'products' AND COLUMN_NAME = 'display_order'),
  'SELECT ''products.display_order already exists'' AS migration_note',
  'ALTER TABLE `products` ADD COLUMN `display_order` int NOT NULL DEFAULT 0'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'products' AND COLUMN_NAME = 'is_active'),
  'SELECT ''products.is_active already exists'' AS migration_note',
  'ALTER TABLE `products` ADD COLUMN `is_active` tinyint(1) NOT NULL DEFAULT 1'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'products' AND COLUMN_NAME = 'created_at'),
  'SELECT ''products.created_at already exists'' AS migration_note',
  'ALTER TABLE `products` ADD COLUMN `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plans' AND COLUMN_NAME = 'product_id'),
  'SELECT ''plans.product_id already exists'' AS migration_note',
  'ALTER TABLE `plans` ADD COLUMN `product_id` varchar(36) DEFAULT NULL'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plans' AND COLUMN_NAME = 'price_label'),
  'SELECT ''plans.price_label already exists'' AS migration_note',
  'ALTER TABLE `plans` ADD COLUMN `price_label` varchar(100) DEFAULT NULL'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plans' AND COLUMN_NAME = 'billing_period'),
  'SELECT ''plans.billing_period already exists'' AS migration_note',
  'ALTER TABLE `plans` ADD COLUMN `billing_period` varchar(100) DEFAULT NULL'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plans' AND COLUMN_NAME = 'api_limit'),
  'SELECT ''plans.api_limit already exists'' AS migration_note',
  'ALTER TABLE `plans` ADD COLUMN `api_limit` int NOT NULL DEFAULT 0'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plans' AND COLUMN_NAME = 'cost'),
  'SELECT ''plans.cost already exists'' AS migration_note',
  'ALTER TABLE `plans` ADD COLUMN `cost` float NOT NULL DEFAULT 0'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plans' AND COLUMN_NAME = 'is_popular'),
  'SELECT ''plans.is_popular already exists'' AS migration_note',
  'ALTER TABLE `plans` ADD COLUMN `is_popular` tinyint(1) NOT NULL DEFAULT 0'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plans' AND COLUMN_NAME = 'is_active'),
  'SELECT ''plans.is_active already exists'' AS migration_note',
  'ALTER TABLE `plans` ADD COLUMN `is_active` tinyint(1) NOT NULL DEFAULT 1'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plan_tools' AND COLUMN_NAME = 'is_active'),
  'SELECT ''plan_tools.is_active already exists'' AS migration_note',
  'ALTER TABLE `plan_tools` ADD COLUMN `is_active` tinyint(1) NOT NULL DEFAULT 1'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = (SELECT IF(
  EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plan_tools' AND COLUMN_NAME = 'display_order'),
  'SELECT ''plan_tools.display_order already exists'' AS migration_note',
  'ALTER TABLE `plan_tools` ADD COLUMN `display_order` int NOT NULL DEFAULT 0'
));
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS `subscription_tools` (
  `id` varchar(36) NOT NULL,
  `subscription_id` varchar(36) NOT NULL,
  `plan_tool_id` varchar(36) NOT NULL,
  `tool_key` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_subscription_tools_plan_tool` (`subscription_id`,`plan_tool_id`),
  UNIQUE KEY `uq_subscription_tools_tool_key` (`subscription_id`,`tool_key`),
  KEY `idx_subscription_tools_plan_tool` (`plan_tool_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `organization_subscription_requests` (
  `id` varchar(36) NOT NULL,
  `organization_id` varchar(36) NOT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'pending',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `approved_at` datetime DEFAULT NULL,
  `rejected_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `organization_id` (`organization_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `organization_subscription_request_items` (
  `id` varchar(36) NOT NULL,
  `request_id` varchar(36) NOT NULL,
  `plan_id` varchar(36) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_org_subscription_request_items_request_plan` (`request_id`,`plan_id`),
  KEY `plan_id` (`plan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `organization_subscription_request_tools` (
  `id` varchar(36) NOT NULL,
  `request_item_id` varchar(36) NOT NULL,
  `plan_tool_id` varchar(36) NOT NULL,
  `tool_key` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_org_subscription_request_tools_plan_tool` (`request_item_id`,`plan_tool_id`),
  UNIQUE KEY `uq_org_subscription_request_tools_tool_key` (`request_item_id`,`tool_key`),
  KEY `plan_tool_id` (`plan_tool_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `plan_upgrade_request_items` (
  `id` varchar(36) NOT NULL,
  `request_id` varchar(36) NOT NULL,
  `plan_id` varchar(36) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_upgrade_request_items_request_plan` (`request_id`,`plan_id`),
  KEY `plan_id` (`plan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `plan_upgrade_request_tools` (
  `id` varchar(36) NOT NULL,
  `request_item_id` varchar(36) NOT NULL,
  `plan_tool_id` varchar(36) NOT NULL,
  `tool_key` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_upgrade_request_tools_plan_tool` (`request_item_id`,`plan_tool_id`),
  UNIQUE KEY `uq_upgrade_request_tools_tool_key` (`request_item_id`,`tool_key`),
  KEY `plan_tool_id` (`plan_tool_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- Standard global roles
-- ---------------------------------------------------------------------------

DROP TEMPORARY TABLE IF EXISTS `tmp_standard_roles`;
CREATE TEMPORARY TABLE `tmp_standard_roles` (
  `name` varchar(255) NOT NULL,
  `permissions` text NOT NULL,
  `description` text
) ENGINE=InnoDB;

INSERT INTO `tmp_standard_roles` (`name`, `permissions`, `description`)
VALUES
('Org Admin / Owner', JSON_ARRAY('forgecatalog:admin','forgesphere:admin','forgefuzz:admin','forgehub:admin','forgearmor:admin','forgeflux:admin','forgeshift:admin','platform_admin:admin'), 'Admin access across all ProbeStack products and platform administration.'),
('Business Unit Admin', JSON_ARRAY('forgecatalog:manage_bu','forgesphere:manage_bu','forgefuzz:manage_bu','forgehub:manage_bu','forgearmor:manage_bu','forgeflux:manage_bu','forgeshift:manage_bu','platform_admin:manage_bu'), 'Manage own Business Unit, projects, and resources under that Business Unit.'),
('Project Admin', JSON_ARRAY('forgecatalog:manage_project','forgesphere:manage_project','forgefuzz:manage_project','forgehub:manage_project','forgearmor:manage_project','forgeflux:manage_project','forgeshift:manage_project','platform_admin:manage_project'), 'Manage own project and related resources under the assigned Business Unit.'),
('Designer', JSON_ARRAY('forgecatalog:edit','forgesphere:edit','forgefuzz:view','forgehub:view','forgearmor:view','forgeflux:view','forgeshift:view','platform_admin:view'), 'Design/edit access in catalog and lifecycle tools with view access elsewhere.'),
('Platform/Lifecycle Owner', JSON_ARRAY('forgecatalog:edit','forgesphere:admin','forgefuzz:view','forgehub:edit','forgearmor:view','forgeflux:approve','forgeshift:view','platform_admin:view'), 'Lifecycle ownership across ForgeSphere with approval/edit access for platform flow.'),
('QA / Test Engineer', JSON_ARRAY('forgecatalog:view','forgesphere:view','forgefuzz:admin','forgehub:view','forgearmor:view','forgeflux:view','forgeshift:view','platform_admin:view'), 'Testing ownership in ForgeFuzz with view access elsewhere.'),
('Platform Engineer', JSON_ARRAY('forgecatalog:edit','forgesphere:edit','forgefuzz:view','forgehub:admin','forgearmor:view','forgeflux:view','forgeshift:view','platform_admin:view'), 'Platform engineering ownership in ForgeHub with edit access to catalog/lifecycle.'),
('Security Engineer / AppSec', JSON_ARRAY('forgecatalog:view','forgesphere:approve','forgefuzz:edit','forgehub:edit','forgearmor:admin','forgeflux:approve','forgeshift:view','platform_admin:edit'), 'Security administration in ForgeArmor with approval/edit access for security workflows.'),
('DevOps / Release Engineer', JSON_ARRAY('forgecatalog:view','forgesphere:edit','forgefuzz:view','forgehub:view','forgearmor:view','forgeflux:admin','forgeshift:edit','platform_admin:view'), 'Release ownership in ForgeFlux with migration/edit access where needed.'),
('API/Agent Consumer', JSON_ARRAY('forgecatalog:view','forgesphere:view','forgefuzz:view','forgehub:view','forgearmor:none','forgeflux:none','forgeshift:none','platform_admin:none'), 'Consumer read access to API and agent-facing products only.'),
('Read-Only / Auditor', JSON_ARRAY('forgecatalog:view','forgesphere:view','forgefuzz:view','forgehub:view','forgearmor:view','forgeflux:view','forgeshift:view','platform_admin:view'), 'Read-only auditor access across all products and platform administration.');

INSERT INTO `roles` (`id`, `name`, `organization_id`, `permissions`, `description`, `created_at`)
SELECT UUID(), sr.`name`, NULL, sr.`permissions`, sr.`description`, UTC_TIMESTAMP()
FROM `tmp_standard_roles` sr
WHERE NOT EXISTS (
  SELECT 1
  FROM `roles` r
  WHERE r.`organization_id` IS NULL
    AND r.`name` = sr.`name`
);

UPDATE `roles` r
JOIN `tmp_standard_roles` sr
  ON r.`organization_id` IS NULL
 AND r.`name` = sr.`name`
SET
  r.`permissions` = sr.`permissions`,
  r.`description` = sr.`description`;

DROP TEMPORARY TABLE IF EXISTS `tmp_user_role_map`;
CREATE TEMPORARY TABLE `tmp_user_role_map` AS
SELECT
  u.`id` AS `user_id`,
  COALESCE(r.`name`, u.`role_name`) AS `old_role_name`
FROM `users` u
LEFT JOIN `roles` r ON r.`id` = u.`role_id`;

UPDATE `users` u
JOIN `tmp_user_role_map` old_roles ON old_roles.`user_id` = u.`id`
JOIN `roles` new_roles
  ON new_roles.`organization_id` IS NULL
 AND new_roles.`name` = CASE
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('admin','org admin','org_admin','owner','org admin / owner') THEN 'Org Admin / Owner'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('business unit admin','bu admin','bu_admin') THEN 'Business Unit Admin'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('project admin','project_admin') THEN 'Project Admin'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('developer','designer') THEN 'Designer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('platform/lifecycle owner','platform lifecycle owner','lifecycle owner') THEN 'Platform/Lifecycle Owner'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('qa / test engineer','qa test engineer','qa','tester','test engineer') THEN 'QA / Test Engineer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('platform engineer') THEN 'Platform Engineer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('security engineer / appsec','security engineer','appsec') THEN 'Security Engineer / AppSec'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('devops / release engineer','devops','release engineer') THEN 'DevOps / Release Engineer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('user','member','individual user','api/agent consumer','api agent consumer') THEN 'API/Agent Consumer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('viewer','read only','read-only','auditor','read-only / auditor') THEN 'Read-Only / Auditor'
    ELSE 'Read-Only / Auditor'
  END
SET
  u.`role_id` = new_roles.`id`,
  u.`role_name` = new_roles.`name`;

DROP TEMPORARY TABLE IF EXISTS `tmp_user_request_role_map`;
CREATE TEMPORARY TABLE `tmp_user_request_role_map` AS
SELECT
  ur.`id` AS `request_id`,
  COALESCE(r.`name`, ur.`requested_role`) AS `old_role_name`
FROM `user_requests` ur
LEFT JOIN `roles` r ON r.`id` = ur.`approved_role_id`;

UPDATE `user_requests` ur
JOIN `tmp_user_request_role_map` old_roles ON old_roles.`request_id` = ur.`id`
JOIN `roles` new_roles
  ON new_roles.`organization_id` IS NULL
 AND new_roles.`name` = CASE
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('admin','org admin','org_admin','owner','org admin / owner') THEN 'Org Admin / Owner'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('business unit admin','bu admin','bu_admin') THEN 'Business Unit Admin'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('project admin','project_admin') THEN 'Project Admin'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('developer','designer') THEN 'Designer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('platform/lifecycle owner','platform lifecycle owner','lifecycle owner') THEN 'Platform/Lifecycle Owner'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('qa / test engineer','qa test engineer','qa','tester','test engineer') THEN 'QA / Test Engineer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('platform engineer') THEN 'Platform Engineer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('security engineer / appsec','security engineer','appsec') THEN 'Security Engineer / AppSec'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('devops / release engineer','devops','release engineer') THEN 'DevOps / Release Engineer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('user','member','individual user','api/agent consumer','api agent consumer') THEN 'API/Agent Consumer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ''))) IN ('viewer','read only','read-only','auditor','read-only / auditor') THEN 'Read-Only / Auditor'
    ELSE 'Read-Only / Auditor'
  END
SET ur.`approved_role_id` = new_roles.`id`
WHERE ur.`approved_role_id` IS NOT NULL;

UPDATE `user_requests` ur
JOIN `tmp_user_request_role_map` old_roles ON old_roles.`request_id` = ur.`id`
SET ur.`requested_role` = CASE
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('admin','org admin','org_admin','owner','org admin / owner') THEN 'Org Admin / Owner'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('business unit admin','bu admin','bu_admin') THEN 'Business Unit Admin'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('project admin','project_admin') THEN 'Project Admin'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('developer','designer') THEN 'Designer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('platform/lifecycle owner','platform lifecycle owner','lifecycle owner') THEN 'Platform/Lifecycle Owner'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('qa / test engineer','qa test engineer','qa','tester','test engineer') THEN 'QA / Test Engineer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('platform engineer') THEN 'Platform Engineer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('security engineer / appsec','security engineer','appsec') THEN 'Security Engineer / AppSec'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('devops / release engineer','devops','release engineer') THEN 'DevOps / Release Engineer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('user','member','individual user','api/agent consumer','api agent consumer') THEN 'API/Agent Consumer'
    WHEN LOWER(TRIM(COALESCE(old_roles.`old_role_name`, ur.`requested_role`, ''))) IN ('viewer','read only','read-only','auditor','read-only / auditor') THEN 'Read-Only / Auditor'
    ELSE 'Read-Only / Auditor'
  END;

-- ---------------------------------------------------------------------------
-- Official product catalog
-- ---------------------------------------------------------------------------

INSERT INTO `products` (`id`, `key`, `name`, `description`, `display_order`, `is_active`, `created_at`)
VALUES
('prod_forgeshift', 'forgeshift', 'ForgeShift - Gateway Migration', 'Automated migration and transformation of API proxies across disparate gateway environments.', 10, 1, UTC_TIMESTAMP()),
('prod_forgestudio', 'forgestudio', 'ForgeStudio - API Design', 'Powerful API design and development studio for modern collaborative teams.', 20, 1, UTC_TIMESTAMP()),
('prod_forgeq', 'forgeq', 'ForgeQ - API, MCP & AI Testing', 'Automated API, MCP & AI testing, SDK, quality assurance, and mock server generation playground.', 30, 1, UTC_TIMESTAMP()),
('prod_forgesphere', 'forgesphere', 'ForgeSphere - API Development Lifecycle', 'Centralized API Lifecycle generation, observability, logging, and comprehensive analytics for your API ecosystem.', 40, 1, UTC_TIMESTAMP()),
('prod_forgeai', 'forgeai', 'ForgeAi - AI Gateway', 'AI Gateway to monitor, secure, and route your LLM & AI provider traffic seamlessly.', 50, 1, UTC_TIMESTAMP()),
('prod_agentic_ai', 'agentic_ai', 'Agentic AI Platform', 'End-to-end intelligent agent workflow orchestration and autonomous task execution.', 60, 1, UTC_TIMESTAMP())
ON DUPLICATE KEY UPDATE
  `name` = VALUES(`name`),
  `description` = VALUES(`description`),
  `display_order` = VALUES(`display_order`),
  `is_active` = VALUES(`is_active`);

DROP TEMPORARY TABLE IF EXISTS `tmp_plan_catalog`;
CREATE TEMPORARY TABLE `tmp_plan_catalog` (
  `id` varchar(36) NOT NULL,
  `product_key` varchar(100) NOT NULL,
  `name` varchar(255) NOT NULL,
  `price_label` varchar(100) DEFAULT NULL,
  `billing_period` varchar(100) DEFAULT NULL,
  `description` text NOT NULL,
  `features` text NOT NULL,
  `cost` float NOT NULL DEFAULT 0,
  `is_popular` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

INSERT INTO `tmp_plan_catalog` (`id`,`product_key`,`name`,`price_label`,`billing_period`,`description`,`features`,`cost`,`is_popular`)
VALUES
('plan_forgeshift_starter','forgeshift','Starter','$0','/mo','Basic migration tools for small teams.',JSON_ARRAY('Up to 10 migrations','Basic UI access','Email support'),0,0),
('plan_forgeshift_enterprise_plus','forgeshift','Enterprise - Plus','Contact Sales',NULL,'Comprehensive migration support.',JSON_ARRAY('100% automated migration & cutover with ZERO DOWNTIME','Unlimited Proxy & Resources migration','Unlimited User & Role Migration','Developer Portal Migration','Integrated inbuilt Proxy Editor with AI enabled','100% Customized product','Migration support Env to Env & Hybrid','Integrated Cloud Storage, Github, CICD, SSO','Integrated with Advance complience','Dedicated PS & migration team','Advanced Dashbord with Report and Alert','8*5 support + SLA','Contact sales : info@probestack.io'),0,0),
('plan_forgestudio_starter','forgestudio','Starter','$0','/month/user','Ideal for small API teams.',JSON_ARRAY('1 user, 2 API (public only), 1 Project','OpenAPI editor (YAML/JSON)','Visual OpenAPI designer','5 Contract Testing','API Linting','Interactive API documentation','OpenAPI + JSON Schema','Community support'),0,0),
('plan_forgestudio_enterprise','forgestudio','Enterprise','$40','/month/user','Advanced collaboration.',JSON_ARRAY('Included Starter Features','Private APIs & Projects','Collaboration (multi-user editing)','Cloning, Versioning & Governance rules','API style validation using Linting','Model Schema Mapping','CICD & Connectors integrations','Team access with 5 users','50 Contracts Testing','SDK / Advanced Linting','Email support'),40,1),
('plan_forgestudio_enterprise_plus','forgestudio','Enterprise - Plus','Contact Sales',NULL,'Dedicated Enterprise for scale.',JSON_ARRAY('Includes Enterprise','Available both SaaS/Self Hosted','Unlimited users','Unlimited API Design','SSO (SAML/LDAP)','Organization, Project & Team management','Audit logs (compliance)','Role-based access control','Advanced templates & governance','Specification Library','AI-native tools (trend): Generate APIs, CICD enabled from prompts, AI validation rules, AI security/compliance scanning, Auto-create OpenAPI specs from APIs, Auto-generate test cases','Contract/Functional Testing','Dedicated infrastructure','Advanced Dashboard','24/7 support'),0,0),
('plan_forgeq_starter','forgeq','Starter','$0','/month/user','Basic testing capabilities.',JSON_ARRAY('Standard API testing','API requests (REST, GraphQL)','Collections Testing','Environment variables','Basic testing scripts','Limited collaboration','Offline-first API testing','Monitoring','Email support'),0,0),
('plan_forgeq_enterprise','forgeq','Enterprise','$30','/month/user','Comprehensive API & MCP testing.',JSON_ARRAY('Includes Starter','API , MCP & Collections Testing','Web Application Testing','Projects & Team Managemnet','Mock servers','Git sync','CI/CD integration','Monitoring + automation','Email support'),30,1),
('plan_forgeq_enterprise_plus','forgeq','Enterprise - Plus','Contact Sales',NULL,'Advanced API, UI, MCP & AI testing.',JSON_ARRAY('Includes Enterprise','Includes Enterprise','SSO & Role-based access','Enterprise sync','Audit logs','Unlimited runs','Load /PerformanceTesting','Monitoring + analytics','API stress testing','API governance','API Security Testing','AI debugging + auto-fix','Integrated  all AI models','AI generate Testcase','AI updates tests automatically','Test data generation','Zero manual test writing','Simulate failures','Latency injection','LLM Model Testing (Coming Soon)','Agentic AI Testing (Coming Soon)','Record & replay testing (Coming Soon)','24/7 support','Contact sales : info@probestack.io'),0,0),
('plan_forgesphere_starter','forgesphere','Starter','$50','/month/user','Basic API Lifecycle.',JSON_ARRAY('Up to 50 Microservice & APIs Proxies','Java Springboot API Generation, View & Edit','Python API Generation, View & Edit','NodeJS API Generation, View & Edit','APIGEE Proxy Generation, View & Edit','API Deploy to GCP ','API Design','Mock service Generation','Contract Testing','TestCase generation','Integrated CICD for API and Proxy Deployment','Automation Functional Testing','Automation Unit Testing','Security Testing','Support Artifctory Registry ','Support Github Action ','Integrated with Cloud connectors AWS, GCP , Azure , Github, Action, Cloud Storage, Apigee, API Linting Connectors ','Integrated with SCM connectors Github, Github Action, API Linting Connectors ','Integrated with Cloud Storage connectors GCS, S3, API Linting Connectors ','Integrated with API Gateway connectors Apigee Connectors ','15-day log retention','Standard dashboards','Email Support'),50,0),
('plan_forgesphere_enterprise','forgesphere','Enterprise','$150','/month/user','Advanced API Lifecycle.',JSON_ARRAY('Includes Starter','Java Springboot API Generation, View, Edit, Clone & Versioning','Python API Generation, View, Edit, Clone & Versioning','NodeJS API Generation, View, Edit, Clone & Versioning','APIGEE Proxy Generation, View, Edit, Clone & Versioning','KONG Service Generation, View, Edit, Clone & Versioning','MULESOFT Api Generation, View, Edit, Clone & Versioning','API Deploy to GCP, Azure & AWS ','API Proxy Deploy to Apigee, Kong & Mulesoft','API Design','Mock service Generation','Contract Testing','TestCase generation','Integrated CICD for API and Proxy Deployment','Automation Functional Testing','Automation Unit Testing','Security Testing','Support Artifctory Registry ','Support Github Action ','API Governance ','Integrated CICD for API and Proxy Deployment','Integrated with Cloud connectors AWS, GCP , Azure Connectors ','Integrated with SCM connectors Github, Github Action, API Linting Connectors ','Integrated with Cloud Storage connectors GCS, S3, API Linting Connectors ','Integrated with API Gateway connectors Apigee, Kong , Mulesoft Connectors ','30-day log retention','Standard dashboards','Priority support'),150,1),
('plan_forgesphere_enterprise_plus','forgesphere','Enterprise - Plus','Contact Sales',NULL,'Unlimited scaled API Lifecycle.',JSON_ARRAY('Includes Enterprise ','SSO & Role-based access','MCP Generation, View, Edit, Clone , Versioning & Deprecation','MCP Expose to Apigee MCP Gateway','Audit logs','Java Springboot API Generation, View, Edit, Clone , Versioning & Deprecation','Python API Generation, View, Edit, Clone , Versioning & Deprecation','NodeJS API Generation, View, Edit, Clone , Versioning & Deprecation','APIGEE Proxy Generation, View, Edit, Clone , Versioning & Deprecation','KONG Service Generation, View, Edit, Clone , Versioning & Deprecation','MULESOFT Api Generation, View, Edit, Clone , Versioning & Deprecation','Apigee Proxy Editor, Debug and Trace ','Kong Service Editor, Debug and Trace','One Click for higher environmnet Deployment','API Advance Governance ','AI-native tools (trend): Generate Microservice , Proxy & CICD enabled from prompts, AI validation rules, AI security/compliance scanning, Auto-create OpenAPI specs from APIs,Auto-generate test cases','Advanced Dashboard','Advanced Analytics','8*5 Support','Contact sales : info@probestack.io'),0,0),
('plan_forgeai_starter','forgeai','Starter','$3,500','/month','Advanced AI traffic routing & observability.',JSON_ARRAY('Up to 200K API Calls/mo','Advanced AI Gateway features','OpenAI, Anthropic, Google LLM Models','Multi-provider LLM routing with 3 Envs','Gateway Dashboard with 30days log.','Rate limiting & throttling','API key management','Request/response logging','Email support'),3500,0),
('plan_forgeai_enterprise','forgeai','Enterprise','$9,500','/month','Advanced AI traffic routing & observability.',JSON_ARRAY('Up to 3M API Calls/mo & SSO / SAML integration','Caching & semantics','Cost allocation & per-team budgets','PII redaction & content filtering','Prompt injection detection','Latency & token analytics dashboard','Priority support'),9500,1),
('plan_forgeai_enterprise_plus','forgeai','Enterprise - Plus','Contact Sales',NULL,'Advanced AI traffic routing & observability.',JSON_ARRAY('Unlimited tokens','Dedicated Infrastructure','Custom model adapters & self-hosted LLMs','99.99% uptime SLA + dedicated support','Fine-grained RBAC per team/model','Private deployment (air-gapped available)','Contact sales : info@probestack.io','24/7 support'),0,0),
('plan_agentic_ai_starter','agentic_ai','Starter','$0','/month/user','Explore autonomous agents.',JSON_ARRAY('Up to 10 autonomous agents','Basic RAG','Email support'),0,0),
('plan_agentic_ai_enterprise','agentic_ai','Enterprise','$100','/month/user','Explore autonomous agents.',JSON_ARRAY('Up to 10 autonomous agents','Basic RAG','Email support'),100,0),
('plan_agentic_ai_enterprise_plus','agentic_ai','Enterprise - Plus','Contact Sales','/ 200 Users','Unlimited agentic workflows.',JSON_ARRAY('Unlimited Agents creation','Agent Inventory, RAG, Multi Model','24/7 support + SLA guarantee'),0,1);

INSERT INTO `plans`
  (`id`,`name`,`product_id`,`tool`,`description`,`features`,`price_monthly`,`price_yearly`,`price_label`,`billing_period`,`api_limit`,`cost`,`is_popular`,`is_active`,`created_at`)
SELECT
  pc.`id`,
  pc.`name`,
  p.`id`,
  p.`key`,
  pc.`description`,
  pc.`features`,
  pc.`cost`,
  pc.`cost`,
  pc.`price_label`,
  pc.`billing_period`,
  0,
  pc.`cost`,
  pc.`is_popular`,
  1,
  UTC_TIMESTAMP()
FROM `tmp_plan_catalog` pc
JOIN `products` p ON p.`key` = pc.`product_key`
ON DUPLICATE KEY UPDATE
  `name` = VALUES(`name`),
  `product_id` = VALUES(`product_id`),
  `tool` = VALUES(`tool`),
  `description` = VALUES(`description`),
  `features` = VALUES(`features`),
  `price_monthly` = VALUES(`price_monthly`),
  `price_yearly` = VALUES(`price_yearly`),
  `price_label` = VALUES(`price_label`),
  `billing_period` = VALUES(`billing_period`),
  `api_limit` = VALUES(`api_limit`),
  `cost` = VALUES(`cost`),
  `is_popular` = VALUES(`is_popular`);

INSERT INTO `plan_tools`
  (`id`,`plan_id`,`name`,`description`,`price_monthly`,`price_yearly`,`is_active`,`display_order`,`created_at`)
SELECT
  CONCAT('pt_', REPLACE(pl.`id`, 'plan_', '')),
  pl.`id`,
  CONCAT(pl.`name`, ' access'),
  pl.`description`,
  0,
  0,
  1,
  0,
  UTC_TIMESTAMP()
FROM `plans` pl
JOIN `tmp_plan_catalog` pc ON pc.`id` = pl.`id`
ON DUPLICATE KEY UPDATE
  `plan_id` = VALUES(`plan_id`),
  `name` = VALUES(`name`),
  `description` = VALUES(`description`),
  `price_monthly` = VALUES(`price_monthly`),
  `price_yearly` = VALUES(`price_yearly`),
  `display_order` = VALUES(`display_order`);

-- ---------------------------------------------------------------------------
-- Verification output
-- ---------------------------------------------------------------------------

SELECT 'global_standard_roles' AS `check_name`, COUNT(*) AS `count`
FROM `roles`
WHERE `organization_id` IS NULL
  AND `name` IN (
    'Org Admin / Owner',
    'Business Unit Admin',
    'Project Admin',
    'Designer',
    'Platform/Lifecycle Owner',
    'QA / Test Engineer',
    'Platform Engineer',
    'Security Engineer / AppSec',
    'DevOps / Release Engineer',
    'API/Agent Consumer',
    'Read-Only / Auditor'
  );

SELECT 'official_products' AS `check_name`, COUNT(*) AS `count`
FROM `products`
WHERE `key` IN ('forgeshift','forgestudio','forgeq','forgesphere','forgeai','agentic_ai');

SELECT 'official_plans' AS `check_name`, COUNT(*) AS `count`
FROM `plans`
WHERE `id` IN (
  'plan_forgeshift_starter',
  'plan_forgeshift_enterprise_plus',
  'plan_forgestudio_starter',
  'plan_forgestudio_enterprise',
  'plan_forgestudio_enterprise_plus',
  'plan_forgeq_starter',
  'plan_forgeq_enterprise',
  'plan_forgeq_enterprise_plus',
  'plan_forgesphere_starter',
  'plan_forgesphere_enterprise',
  'plan_forgesphere_enterprise_plus',
  'plan_forgeai_starter',
  'plan_forgeai_enterprise',
  'plan_forgeai_enterprise_plus',
  'plan_agentic_ai_starter',
  'plan_agentic_ai_enterprise',
  'plan_agentic_ai_enterprise_plus'
);

SELECT 'official_plan_tools' AS `check_name`, COUNT(*) AS `count`
FROM `plan_tools`
WHERE `plan_id` IN (
  'plan_forgeshift_starter',
  'plan_forgeshift_enterprise_plus',
  'plan_forgestudio_starter',
  'plan_forgestudio_enterprise',
  'plan_forgestudio_enterprise_plus',
  'plan_forgeq_starter',
  'plan_forgeq_enterprise',
  'plan_forgeq_enterprise_plus',
  'plan_forgesphere_starter',
  'plan_forgesphere_enterprise',
  'plan_forgesphere_enterprise_plus',
  'plan_forgeai_starter',
  'plan_forgeai_enterprise',
  'plan_forgeai_enterprise_plus',
  'plan_agentic_ai_starter',
  'plan_agentic_ai_enterprise',
  'plan_agentic_ai_enterprise_plus'
);
