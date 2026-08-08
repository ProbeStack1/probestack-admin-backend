-- Standardize roles globally across all organizations.
--
-- This removes custom/per-organization role definitions and recreates one
-- shared role catalog. Existing users and approved user requests are remapped
-- to the closest standard global role by their previous role name.
--
-- Take a database backup before running.

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

ALTER TABLE `roles` MODIFY COLUMN `organization_id` varchar(36) DEFAULT NULL;

DROP TEMPORARY TABLE IF EXISTS `tmp_user_role_map`;
CREATE TEMPORARY TABLE `tmp_user_role_map` AS
SELECT
  u.`id` AS `user_id`,
  COALESCE(r.`name`, u.`role_name`) AS `old_role_name`
FROM `users` u
LEFT JOIN `roles` r ON r.`id` = u.`role_id`;

DROP TEMPORARY TABLE IF EXISTS `tmp_user_request_role_map`;
CREATE TEMPORARY TABLE `tmp_user_request_role_map` AS
SELECT
  ur.`id` AS `request_id`,
  COALESCE(r.`name`, ur.`requested_role`) AS `old_role_name`
FROM `user_requests` ur
LEFT JOIN `roles` r ON r.`id` = ur.`approved_role_id`;

SET FOREIGN_KEY_CHECKS = 0;
DELETE FROM `roles`;
SET FOREIGN_KEY_CHECKS = 1;

INSERT INTO `roles` (`id`, `name`, `organization_id`, `permissions`, `description`, `created_at`)
SELECT
  UUID(),
  role_catalog.`name`,
  NULL,
  role_catalog.`permissions`,
  role_catalog.`description`,
  UTC_TIMESTAMP()
FROM (
  SELECT 'Org Admin / Owner' AS `name`,
    JSON_ARRAY('forgecatalog:admin','forgesphere:admin','forgefuzz:admin','forgehub:admin','forgearmor:admin','forgeflux:admin','forgeshift:admin','platform_admin:admin') AS `permissions`,
    'Admin access across all ProbeStack products and platform administration.' AS `description`
  UNION ALL SELECT 'Business Unit Admin',
    JSON_ARRAY('forgecatalog:manage_bu','forgesphere:manage_bu','forgefuzz:manage_bu','forgehub:manage_bu','forgearmor:manage_bu','forgeflux:manage_bu','forgeshift:manage_bu','platform_admin:manage_bu'),
    'Manage own Business Unit, projects, and resources under that Business Unit.'
  UNION ALL SELECT 'Project Admin',
    JSON_ARRAY('forgecatalog:manage_project','forgesphere:manage_project','forgefuzz:manage_project','forgehub:manage_project','forgearmor:manage_project','forgeflux:manage_project','forgeshift:manage_project','platform_admin:manage_project'),
    'Manage own project and related resources under the assigned Business Unit.'
  UNION ALL SELECT 'Designer',
    JSON_ARRAY('forgecatalog:edit','forgesphere:edit','forgefuzz:view','forgehub:view','forgearmor:view','forgeflux:view','forgeshift:view','platform_admin:view'),
    'Design/edit access in catalog and lifecycle tools with view access elsewhere.'
  UNION ALL SELECT 'Platform/Lifecycle Owner',
    JSON_ARRAY('forgecatalog:edit','forgesphere:admin','forgefuzz:view','forgehub:edit','forgearmor:view','forgeflux:approve','forgeshift:view','platform_admin:view'),
    'Lifecycle ownership across ForgeSphere with approval/edit access for platform flow.'
  UNION ALL SELECT 'QA / Test Engineer',
    JSON_ARRAY('forgecatalog:view','forgesphere:view','forgefuzz:admin','forgehub:view','forgearmor:view','forgeflux:view','forgeshift:view','platform_admin:view'),
    'Testing ownership in ForgeFuzz with view access elsewhere.'
  UNION ALL SELECT 'Platform Engineer',
    JSON_ARRAY('forgecatalog:edit','forgesphere:edit','forgefuzz:view','forgehub:admin','forgearmor:view','forgeflux:view','forgeshift:view','platform_admin:view'),
    'Platform engineering ownership in ForgeHub with edit access to catalog/lifecycle.'
  UNION ALL SELECT 'Security Engineer / AppSec',
    JSON_ARRAY('forgecatalog:view','forgesphere:approve','forgefuzz:edit','forgehub:edit','forgearmor:admin','forgeflux:approve','forgeshift:view','platform_admin:edit'),
    'Security administration in ForgeArmor with approval/edit access for security workflows.'
  UNION ALL SELECT 'DevOps / Release Engineer',
    JSON_ARRAY('forgecatalog:view','forgesphere:edit','forgefuzz:view','forgehub:view','forgearmor:view','forgeflux:admin','forgeshift:edit','platform_admin:view'),
    'Release ownership in ForgeFlux with migration/edit access where needed.'
  UNION ALL SELECT 'API/Agent Consumer',
    JSON_ARRAY('forgecatalog:view','forgesphere:view','forgefuzz:view','forgehub:view','forgearmor:none','forgeflux:none','forgeshift:none','platform_admin:none'),
    'Consumer read access to API and agent-facing products only.'
  UNION ALL SELECT 'Read-Only / Auditor',
    JSON_ARRAY('forgecatalog:view','forgesphere:view','forgefuzz:view','forgehub:view','forgearmor:view','forgeflux:view','forgeshift:view','platform_admin:view'),
    'Read-only auditor access across all products and platform administration.'
) role_catalog;

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

SELECT
  CASE WHEN `organization_id` IS NULL THEN 'global' ELSE `organization_id` END AS `role_scope`,
  COUNT(*) AS `standard_role_count`
FROM `roles`
GROUP BY `organization_id`;
