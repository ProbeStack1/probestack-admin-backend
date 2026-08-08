-- Seed configurable ForgeShift migration options as plan selectable features.
-- These rows are intentionally editable in the Product Plans UI.

INSERT INTO `plan_tools` (`id`, `plan_id`, `name`, `description`, `price_monthly`, `price_yearly`, `is_active`, `display_order`, `created_at`)
SELECT UUID(), 'plan_forgeshift_starter', migration_name, migration_description, 0, 0, 1, display_order, UTC_TIMESTAMP()
FROM (
    SELECT 'Apigee Edge to Apigee X' AS migration_name, 'Migrate proxies and policies from Apigee Edge to Apigee X.' AS migration_description, 10 AS display_order
    UNION ALL SELECT 'WSO2 to Kong', 'Migrate APIs and gateway configuration from WSO2 API Manager to Kong.', 20
    UNION ALL SELECT 'Kong to Apigee X', 'Migrate services, routes, plugins, and API definitions from Kong to Apigee X.', 30
    UNION ALL SELECT 'MuleSoft to Apigee X', 'Migrate MuleSoft APIs and gateway assets to Apigee X.', 40
) defaults
WHERE EXISTS (SELECT 1 FROM `plans` WHERE `id` = 'plan_forgeshift_starter')
  AND NOT EXISTS (
      SELECT 1 FROM `plan_tools`
      WHERE `plan_id` = 'plan_forgeshift_starter'
        AND `name` = defaults.migration_name
  );

INSERT INTO `plan_tools` (`id`, `plan_id`, `name`, `description`, `price_monthly`, `price_yearly`, `is_active`, `display_order`, `created_at`)
SELECT UUID(), 'plan_forgeshift_enterprise_plus', migration_name, migration_description, 0, 0, 1, display_order, UTC_TIMESTAMP()
FROM (
    SELECT 'Apigee Edge to Apigee X' AS migration_name, 'Migrate proxies and policies from Apigee Edge to Apigee X.' AS migration_description, 10 AS display_order
    UNION ALL SELECT 'Apigee OPDK to Apigee X', 'Migrate from Apigee OPDK/private cloud to Apigee X.', 20
    UNION ALL SELECT 'Apigee Edge to Apigee Hybrid', 'Migrate Apigee Edge proxies to Apigee Hybrid.', 30
    UNION ALL SELECT 'Apigee OPDK to Apigee Hybrid', 'Migrate Apigee OPDK/private cloud assets to Apigee Hybrid.', 40
    UNION ALL SELECT 'Apigee Edge to Kong', 'Migrate Apigee Edge proxies, policies, and products to Kong.', 50
    UNION ALL SELECT 'Apigee X to Kong', 'Migrate Apigee X proxies and API products to Kong.', 60
    UNION ALL SELECT 'WSO2 to Kong', 'Migrate APIs and gateway configuration from WSO2 API Manager to Kong.', 70
    UNION ALL SELECT 'WSO2 to Apigee X', 'Migrate WSO2 APIs and gateway policies to Apigee X.', 80
    UNION ALL SELECT 'Kong to Apigee X', 'Migrate Kong services, routes, plugins, and API definitions to Apigee X.', 90
    UNION ALL SELECT 'Kong to WSO2', 'Migrate Kong APIs, routes, and gateway configuration to WSO2 API Manager.', 100
    UNION ALL SELECT 'MuleSoft to Apigee X', 'Migrate MuleSoft APIs and gateway assets to Apigee X.', 110
    UNION ALL SELECT 'MuleSoft to Kong', 'Migrate MuleSoft APIs and gateway assets to Kong.', 120
) defaults
WHERE EXISTS (SELECT 1 FROM `plans` WHERE `id` = 'plan_forgeshift_enterprise_plus')
  AND NOT EXISTS (
      SELECT 1 FROM `plan_tools`
      WHERE `plan_id` = 'plan_forgeshift_enterprise_plus'
        AND `name` = defaults.migration_name
  );
