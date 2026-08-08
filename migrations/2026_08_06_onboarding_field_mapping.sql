-- Align organization, business unit, project, and application onboarding fields
-- with onboarding_field_mapping.xlsx.

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

DROP PROCEDURE IF EXISTS add_onboarding_column;
DELIMITER //
CREATE PROCEDURE add_onboarding_column(
  IN table_name_in VARCHAR(64),
  IN column_name_in VARCHAR(64),
  IN column_definition_in TEXT
)
BEGIN
  SET @column_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = table_name_in
      AND COLUMN_NAME = column_name_in
  );
  SET @column_sql = IF(
    @column_exists = 0,
    CONCAT('ALTER TABLE `', table_name_in, '` ADD COLUMN `', column_name_in, '` ', column_definition_in),
    'SELECT 1'
  );
  PREPARE column_stmt FROM @column_sql;
  EXECUTE column_stmt;
  DEALLOCATE PREPARE column_stmt;
END //
DELIMITER ;

CALL add_onboarding_column('organizations', 'organization_code', 'VARCHAR(100) NULL');
CALL add_onboarding_column('organizations', 'legal_name', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'industry', 'VARCHAR(100) NULL');
CALL add_onboarding_column('organizations', 'business_type', 'VARCHAR(50) NULL');
CALL add_onboarding_column('organizations', 'country', 'VARCHAR(100) NULL');
CALL add_onboarding_column('organizations', 'region', 'VARCHAR(100) NULL');
CALL add_onboarding_column('organizations', 'time_zone', 'VARCHAR(100) NULL');
CALL add_onboarding_column('organizations', 'headquarters', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'default_currency', 'VARCHAR(20) NULL');
CALL add_onboarding_column('organizations', 'billing_account', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'cost_center', 'VARCHAR(100) NULL');
CALL add_onboarding_column('organizations', 'tax_id', 'VARCHAR(100) NULL');
CALL add_onboarding_column('organizations', 'website', 'VARCHAR(500) NULL');
CALL add_onboarding_column('organizations', 'logo_url', 'TEXT NULL');
CALL add_onboarding_column('organizations', 'primary_contact_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('organizations', 'executive_sponsor_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('organizations', 'technical_contact_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('organizations', 'security_contact_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('organizations', 'identity_provider', 'VARCHAR(50) NULL');
CALL add_onboarding_column('organizations', 'sso_enabled', 'BOOL NOT NULL DEFAULT FALSE');
CALL add_onboarding_column('organizations', 'scim_enabled', 'BOOL NOT NULL DEFAULT FALSE');
CALL add_onboarding_column('organizations', 'mfa_required', 'BOOL NOT NULL DEFAULT FALSE');
CALL add_onboarding_column('organizations', 'default_api_gateway', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'default_ai_gateway', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'default_mcp_gateway', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'default_api_design_tool', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'default_api_testing_tool', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'api_agent_lifecycle_stage', 'VARCHAR(100) NULL');
CALL add_onboarding_column('organizations', 'default_api_inventory', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'cloud_provider', 'VARCHAR(100) NULL');
CALL add_onboarding_column('organizations', 'kubernetes_platform', 'VARCHAR(100) NULL');
CALL add_onboarding_column('organizations', 'default_environment_strategy', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'compliance_standards', 'TEXT NULL');
CALL add_onboarding_column('organizations', 'encryption_standard', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'data_residency', 'VARCHAR(255) NULL');
CALL add_onboarding_column('organizations', 'created_by', 'VARCHAR(36) NULL');

CALL add_onboarding_column('business_units', 'display_name', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'parent_business_unit_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('business_units', 'division', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'department', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'line_of_business', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'business_executive_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('business_units', 'business_owner_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('business_units', 'product_owner_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('business_units', 'technical_owner_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('business_units', 'enterprise_architect_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('business_units', 'platform_owner_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('business_units', 'security_owner_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('business_units', 'compliance_officer_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('business_units', 'support_team', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'operations_team', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'cost_center', 'VARCHAR(100) NULL');
CALL add_onboarding_column('business_units', 'budget', 'FLOAT NULL');
CALL add_onboarding_column('business_units', 'chargeback_model', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'billing_account', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'monthly_budget', 'FLOAT NULL');
CALL add_onboarding_column('business_units', 'annual_budget', 'FLOAT NULL');
CALL add_onboarding_column('business_units', 'ai_budget', 'FLOAT NULL');
CALL add_onboarding_column('business_units', 'api_budget', 'FLOAT NULL');
CALL add_onboarding_column('business_units', 'cloud_provider', 'VARCHAR(100) NULL');
CALL add_onboarding_column('business_units', 'region', 'VARCHAR(100) NULL');
CALL add_onboarding_column('business_units', 'kubernetes_cluster', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'namespace', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'api_gateway', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'ai_gateway', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'logging_platform', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'monitoring_platform', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'secret_manager', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'approval_workflow', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'risk_classification', 'VARCHAR(50) NULL');
CALL add_onboarding_column('business_units', 'business_criticality', 'VARCHAR(50) NULL');
CALL add_onboarding_column('business_units', 'data_classification', 'VARCHAR(50) NULL');
CALL add_onboarding_column('business_units', 'regulatory_standards', 'TEXT NULL');
CALL add_onboarding_column('business_units', 'retention_policy', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'backup_policy', 'VARCHAR(255) NULL');
CALL add_onboarding_column('business_units', 'dr_enabled', 'BOOL NOT NULL DEFAULT FALSE');
CALL add_onboarding_column('business_units', 'sla_tier', 'VARCHAR(50) NULL');

CALL add_onboarding_column('projects', 'project_type', 'VARCHAR(100) NULL');
CALL add_onboarding_column('projects', 'portfolio', 'VARCHAR(255) NULL');
CALL add_onboarding_column('projects', 'project_manager_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('projects', 'product_manager_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('projects', 'scrum_master_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('projects', 'technical_lead_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('projects', 'security_lead_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('projects', 'devops_lead_id', 'VARCHAR(36) NULL');
CALL add_onboarding_column('projects', 'methodology', 'VARCHAR(100) NULL');
CALL add_onboarding_column('projects', 'sprint_duration', 'VARCHAR(100) NULL');
CALL add_onboarding_column('projects', 'repository', 'VARCHAR(500) NULL');
CALL add_onboarding_column('projects', 'cicd_tool', 'VARCHAR(255) NULL');
CALL add_onboarding_column('projects', 'issue_tracker', 'VARCHAR(255) NULL');
CALL add_onboarding_column('projects', 'documentation_url', 'VARCHAR(500) NULL');
CALL add_onboarding_column('projects', 'authentication_method', 'VARCHAR(255) NULL');
CALL add_onboarding_column('projects', 'authorization_method', 'VARCHAR(255) NULL');
CALL add_onboarding_column('projects', 'oauth_provider', 'VARCHAR(255) NULL');
CALL add_onboarding_column('projects', 'mtls_enabled', 'BOOL NOT NULL DEFAULT FALSE');
CALL add_onboarding_column('projects', 'jwt_enabled', 'BOOL NOT NULL DEFAULT FALSE');
CALL add_onboarding_column('projects', 'api_key_enabled', 'BOOL NOT NULL DEFAULT FALSE');
CALL add_onboarding_column('projects', 'secrets_vault', 'VARCHAR(255) NULL');
CALL add_onboarding_column('projects', 'pci_applicable', 'BOOL NOT NULL DEFAULT FALSE');
CALL add_onboarding_column('projects', 'standard_rules', 'TEXT NULL');
CALL add_onboarding_column('projects', 'custom_rules', 'TEXT NULL');
CALL add_onboarding_column('projects', 'owasp_top10_enabled', 'BOOL NOT NULL DEFAULT FALSE');
CALL add_onboarding_column('projects', 'linting_enabled', 'BOOL NOT NULL DEFAULT FALSE');

CREATE TABLE IF NOT EXISTS `project_environments` (
  `id` varchar(36) NOT NULL,
  `project_id` varchar(36) NOT NULL,
  `environment_type` varchar(50) NOT NULL,
  `endpoint_url` varchar(500) DEFAULT NULL,
  `is_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_project_environments_project_type` (`project_id`, `environment_type`)
);

CREATE TABLE IF NOT EXISTS `applications` (
  `id` varchar(36) NOT NULL,
  `project_id` varchar(36) NOT NULL,
  `organization_id` varchar(36) NOT NULL,
  `application_name` varchar(255) NOT NULL,
  `display_name` varchar(255) DEFAULT NULL,
  `description` text,
  `business_capability` varchar(255) DEFAULT NULL,
  `domain` varchar(255) DEFAULT NULL,
  `application_type` varchar(100) DEFAULT NULL,
  `criticality` varchar(50) DEFAULT NULL,
  `runtime` varchar(100) DEFAULT NULL,
  `language` varchar(100) DEFAULT NULL,
  `framework` varchar(100) DEFAULT NULL,
  `version` varchar(100) DEFAULT NULL,
  `container_image` varchar(500) DEFAULT NULL,
  `kubernetes_namespace` varchar(255) DEFAULT NULL,
  `cluster` varchar(255) DEFAULT NULL,
  `api_count` int DEFAULT 0,
  `api_gateway` varchar(255) DEFAULT NULL,
  `base_url` varchar(500) DEFAULT NULL,
  `openapi_spec_url` varchar(500) DEFAULT NULL,
  `asyncapi_spec_url` varchar(500) DEFAULT NULL,
  `graphql_enabled` tinyint(1) DEFAULT 0,
  `webhooks_enabled` tinyint(1) DEFAULT 0,
  `llm_provider` varchar(255) DEFAULT NULL,
  `default_model` varchar(255) DEFAULT NULL,
  `embedding_model` varchar(255) DEFAULT NULL,
  `ai_gateway` varchar(255) DEFAULT NULL,
  `vector_database` varchar(255) DEFAULT NULL,
  `prompt_registry` varchar(255) DEFAULT NULL,
  `mcp_enabled` tinyint(1) DEFAULT 0,
  `mcp_server` varchar(255) DEFAULT NULL,
  `mcp_resources` text,
  `mcp_tools` text,
  `mcp_prompts` text,
  `created_by` varchar(36) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_applications_project_name` (`project_id`, `application_name`)
);

CREATE TABLE IF NOT EXISTS `application_agents` (
  `application_id` varchar(36) NOT NULL,
  `agent_enabled` tinyint(1) DEFAULT 0,
  `planner` varchar(255) DEFAULT NULL,
  `executor` varchar(255) DEFAULT NULL,
  `memory` varchar(255) DEFAULT NULL,
  `knowledge_base` varchar(255) DEFAULT NULL,
  `multi_agent_enabled` tinyint(1) DEFAULT 0,
  `workflow` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`application_id`)
);

CREATE TABLE IF NOT EXISTS `application_monitoring` (
  `application_id` varchar(36) NOT NULL,
  `logging` varchar(255) DEFAULT NULL,
  `metrics` varchar(255) DEFAULT NULL,
  `tracing` varchar(255) DEFAULT NULL,
  `alerts` varchar(255) DEFAULT NULL,
  `dashboards` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`application_id`)
);

CREATE TABLE IF NOT EXISTS `application_security` (
  `application_id` varchar(36) NOT NULL,
  `oauth_enabled` tinyint(1) DEFAULT 0,
  `jwt_enabled` tinyint(1) DEFAULT 0,
  `api_key_enabled` tinyint(1) DEFAULT 0,
  `mtls_enabled` tinyint(1) DEFAULT 0,
  `dlp_enabled` tinyint(1) DEFAULT 0,
  `waf_enabled` tinyint(1) DEFAULT 0,
  `encryption_standard` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`application_id`)
);

CREATE TABLE IF NOT EXISTS `application_billing` (
  `application_id` varchar(36) NOT NULL,
  `cost_center` varchar(100) DEFAULT NULL,
  `monthly_budget` float DEFAULT NULL,
  `token_budget` int DEFAULT NULL,
  `api_budget` int DEFAULT NULL,
  PRIMARY KEY (`application_id`)
);

CREATE TABLE IF NOT EXISTS `quotas` (
  `id` varchar(36) NOT NULL,
  `entity_type` varchar(50) NOT NULL,
  `entity_id` varchar(36) NOT NULL,
  `quota_type` varchar(100) NOT NULL,
  `quota_limit` float DEFAULT NULL,
  `quota_used` float DEFAULT 0,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_quotas_entity_type` (`entity_type`, `entity_id`, `quota_type`)
);

DROP PROCEDURE IF EXISTS add_onboarding_column;
