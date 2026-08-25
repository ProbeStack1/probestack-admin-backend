-- Restore product user roles from db_Cloud_SQL_Export_2026-08-24 (00_44_19).sql.
--
-- The export contains an older users dump with role_name values and a later
-- users dump with role_id values. Role names are used here so this repair is
-- stable across role UUID changes. Rows are matched by email + organization_id.

START TRANSACTION;

DROP TEMPORARY TABLE IF EXISTS restore_user_roles_from_export;

CREATE TEMPORARY TABLE restore_user_roles_from_export (
  email VARCHAR(255) NOT NULL,
  organization_id VARCHAR(36) NOT NULL,
  role_name VARCHAR(255) NOT NULL,
  source_note VARCHAR(100) NOT NULL,
  PRIMARY KEY (email, organization_id)
);

INSERT INTO restore_user_roles_from_export (email, organization_id, role_name, source_note) VALUES
  ('demo@fiserv.com', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'API/Agent Consumer', 'legacy-role-name'),
  ('info@fisglobal.com', '5f7d186a-4b27-4b55-b87a-a5c3396d4274', 'Org Admin / Owner', 'legacy-role-name'),
  ('user@fiserv.com', 'cee2e51d-3b9d-4a21-9ff9-c2dcebe8e619', 'Org Admin / Owner', 'legacy-role-name'),
  ('shivi.o@krelixir.com', 'e537316e-6713-46da-9319-81db71c629fd', 'Org Admin / Owner', 'legacy-role-name'),
  ('admin@fisglobal.com', '5f7d186a-4b27-4b55-b87a-a5c3396d4274', 'Org Admin / Owner', 'legacy-role-name'),
  ('admin@forgecrux.com', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'Org Admin / Owner', 'legacy-role-name'),
  ('admin@krelixir.com', 'e537316e-6713-46da-9319-81db71c629fd', 'Org Admin / Owner', 'legacy-role-name'),
  ('srichandan.mohapatra@probestack.io', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'Business Unit Admin', 'latest-export-role'),
  ('maya.thompson@accera.io', 'e5600eee-167d-4c8b-8888-a6635bd12922', 'Org Admin / Owner', 'latest-export-role'),
  ('ethan.brooks@accera.io', 'e5600eee-167d-4c8b-8888-a6635bd12922', 'Platform/Lifecycle Owner', 'latest-export-role'),
  ('saili.jaguste@forgecrux.com', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'API/Agent Consumer', 'latest-export-role'),
  ('rohan.desai@krelixir.com', '223beb5c-741b-4523-9c23-44fa9c50f46e', 'API/Agent Consumer', 'latest-export-role'),
  ('arjun.mehta@krelixir.com', '223beb5c-741b-4523-9c23-44fa9c50f46e', 'Platform/Lifecycle Owner', 'latest-export-role'),
  ('adarsha.maharana@probestack.io', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'QA / Test Engineer', 'latest-export-role'),
  ('jagruti.dhadiwal@probestack.io', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'Business Unit Admin', 'latest-export-role'),
  ('sarita.parida@probestack.io', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'Business Unit Admin', 'latest-export-role'),
  ('sofia.ramirez@accera.io', 'e5600eee-167d-4c8b-8888-a6635bd12922', 'Platform Engineer', 'latest-export-role'),
  ('simran.dash@probestack.io', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'Business Unit Admin', 'latest-export-role'),
  ('ava.mitchell@accera.io', 'e5600eee-167d-4c8b-8888-a6635bd12922', 'Read-Only / Auditor', 'latest-export-role'),
  ('liam.carter@accera.io', 'e5600eee-167d-4c8b-8888-a6635bd12922', 'API/Agent Consumer', 'latest-export-role'),
  ('priya.nair@krelixir.com', '223beb5c-741b-4523-9c23-44fa9c50f46e', 'Org Admin / Owner', 'latest-export-role'),
  ('neha.kapoor@krelixir.com', '223beb5c-741b-4523-9c23-44fa9c50f46e', 'Platform Engineer', 'latest-export-role'),
  ('kavya.iyer@krelixir.com', '223beb5c-741b-4523-9c23-44fa9c50f46e', 'Read-Only / Auditor', 'latest-export-role'),
  ('khitish.mangal@probestack.io', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'DevOps / Release Engineer', 'latest-export-role'),
  ('himanshu.nag@probestack.io', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'Designer', 'latest-export-role'),
  ('ankit.ostwal@probestack.io', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'Designer', 'latest-export-role'),
  ('sri@probestack.io', 'f52c02e6-d67a-4bc9-8e94-36e9d4b8d30c', 'Business Unit Admin', 'latest-export-role');

-- Preview rows that will not be updated because the user or target role is missing.
SELECT
  restore.email,
  restore.organization_id,
  restore.role_name,
  CASE
    WHEN u.id IS NULL THEN 'missing_user'
    WHEN r.id IS NULL THEN 'missing_role'
    ELSE 'ok'
  END AS restore_status
FROM restore_user_roles_from_export restore
LEFT JOIN users u
  ON LOWER(u.email) = LOWER(restore.email)
 AND u.organization_id = restore.organization_id
LEFT JOIN roles r
  ON r.name = restore.role_name
 AND r.organization_id IS NULL
WHERE u.id IS NULL OR r.id IS NULL;

UPDATE users u
JOIN restore_user_roles_from_export restore
  ON LOWER(u.email) = LOWER(restore.email)
 AND u.organization_id = restore.organization_id
JOIN roles r
  ON r.name = restore.role_name
 AND r.organization_id IS NULL
SET u.role_id = r.id
WHERE u.role_id <> r.id;

-- Verify the restored roles.
SELECT
  u.id,
  u.email,
  u.organization_id,
  r.name AS restored_role_name,
  restore.source_note
FROM users u
JOIN restore_user_roles_from_export restore
  ON LOWER(u.email) = LOWER(restore.email)
 AND u.organization_id = restore.organization_id
JOIN roles r
  ON r.id = u.role_id
ORDER BY u.email;

COMMIT;
