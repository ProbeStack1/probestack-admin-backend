CREATE TABLE IF NOT EXISTS notification_group_emails (
    id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255) NULL,
    is_active BOOL NOT NULL DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_notification_group_emails_email (email)
);

INSERT IGNORE INTO notification_group_emails (id, email, name, is_active, created_at, updated_at)
VALUES
    (UUID(), 'admin@forgecrux.com', 'ForgeCrux Admin', TRUE, NOW(), NOW()),
    (UUID(), 'admin@probestack.io', 'ProbeStack Admin', TRUE, NOW(), NOW()),
    (UUID(), 'saili.jaguste@probestack.io', 'Saili Jaguste', TRUE, NOW(), NOW()),
    (UUID(), 'saili.jaguste@gmail.com', 'Saili Jaguste', TRUE, NOW(), NOW());

INSERT INTO system_settings (`key`, `value`, updated_at, updated_by)
SELECT 'notification_group_initialized', 'true', NOW(), NULL
WHERE NOT EXISTS (
    SELECT 1 FROM system_settings WHERE `key` = 'notification_group_initialized'
);
