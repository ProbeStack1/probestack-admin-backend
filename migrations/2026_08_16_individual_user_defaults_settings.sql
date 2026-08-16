-- Move individual-user defaults into system_settings.
-- The backend reads these settings first and keeps code fallbacks for compatibility.

INSERT INTO `system_settings` (`key`, `value`, `updated_at`, `updated_by`)
VALUES
  ('individual_users_org_id', 'no_organization', UTC_TIMESTAMP(), 'migration'),
  ('individual_users_org_name', 'Individual Users', UTC_TIMESTAMP(), 'migration'),
  ('individual_users_org_email', 'individual@probestack.io', UTC_TIMESTAMP(), 'migration'),
  ('individual_users_contact_person', 'System', UTC_TIMESTAMP(), 'migration'),
  ('individual_default_plan_ids', '["plan_forgeq_starter","plan_agentic_ai_starter"]', UTC_TIMESTAMP(), 'migration')
ON DUPLICATE KEY UPDATE
  `value` = VALUES(`value`),
  `updated_at` = VALUES(`updated_at`),
  `updated_by` = VALUES(`updated_by`);
