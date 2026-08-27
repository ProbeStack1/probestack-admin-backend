CREATE TABLE IF NOT EXISTS user_role_assignments (
    id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_role_assignments_user_role (user_id, role_id),
    KEY idx_user_role_assignments_user_id (user_id),
    KEY idx_user_role_assignments_role_id (role_id),
    CONSTRAINT fk_user_role_assignments_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_user_role_assignments_role
        FOREIGN KEY (role_id) REFERENCES roles(id)
        ON DELETE RESTRICT
);

INSERT INTO user_role_assignments (id, user_id, role_id, created_at)
SELECT UUID(), u.id, u.role_id, COALESCE(u.created_at, NOW())
FROM users u
LEFT JOIN user_role_assignments ura
    ON ura.user_id = u.id
    AND ura.role_id = u.role_id
WHERE u.role_id IS NOT NULL
    AND ura.id IS NULL;
