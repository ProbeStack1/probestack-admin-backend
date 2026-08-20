-- Allow upgrade requests to store multiple current plan IDs as JSON text.

ALTER TABLE `plan_upgrade_requests`
  MODIFY COLUMN `current_plan_id` TEXT NOT NULL;
