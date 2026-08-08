CREATE TABLE IF NOT EXISTS `system_settings` (
  `key` varchar(100) NOT NULL,
  `value` text NOT NULL,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `updated_by` varchar(36) DEFAULT NULL,
  PRIMARY KEY (`key`)
);

INSERT INTO `system_settings` (`key`, `value`, `updated_at`, `updated_by`)
VALUES ('active_identity_provider', 'zitadel', UTC_TIMESTAMP(), NULL)
ON DUPLICATE KEY UPDATE `value` = `value`;
