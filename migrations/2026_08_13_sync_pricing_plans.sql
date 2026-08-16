-- Sync product and plan catalog with the public pricing page.
-- Source: https://probestack.io/pricing, fetched 2026-08-13.
--
-- This migration preserves existing product keys and plan IDs so current
-- subscriptions, onboarding requests, and upgrade requests remain linked.

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

INSERT INTO `products` (`id`, `key`, `name`, `description`, `display_order`, `is_active`, `created_at`)
VALUES
('prod_forgeshift', 'forgeshift', 'ForgeShift - API Gateway Migration', 'Automated migration and transformation of API proxies across disparate gateway environments.', 10, 1, UTC_TIMESTAMP()),
('prod_forgestudio', 'forgestudio', 'ForgeCatalog - API & MCP Design', 'Powerful API design and development studio for modern collaborative teams.', 20, 1, UTC_TIMESTAMP()),
('prod_forgeq', 'forgeq', 'ForgeFuzz - Enterprise API, LLM, MCP, Agent Testing', 'Automated API, MCP & AI testing, SDK, quality assurance, and mock server generation playground.', 30, 1, UTC_TIMESTAMP()),
('prod_forgesphere', 'forgesphere', 'ForgeSphere - API, MCP & Agentic AI Lifecycle', 'Centralized API Lifecycle generation, observability, logging, and comprehensive analytics for your API ecosystem.', 40, 1, UTC_TIMESTAMP()),
('prod_forgeai', 'forgeai', 'ForgeAi - AI & MCP Gateway', 'AI Gateway to monitor, secure, and route your LLM & AI provider traffic seamlessly.', 50, 1, UTC_TIMESTAMP()),
('prod_agentic_ai', 'agentic_ai', 'Agentic AI Platform', 'End-to-end intelligent agent workflow orchestration and autonomous task execution.', 60, 1, UTC_TIMESTAMP())
ON DUPLICATE KEY UPDATE
  `name` = VALUES(`name`),
  `description` = VALUES(`description`),
  `display_order` = VALUES(`display_order`),
  `is_active` = VALUES(`is_active`);

DROP TEMPORARY TABLE IF EXISTS `tmp_pricing_plan_catalog`;
CREATE TEMPORARY TABLE `tmp_pricing_plan_catalog` (
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

INSERT INTO `tmp_pricing_plan_catalog` (`id`,`product_key`,`name`,`price_label`,`billing_period`,`description`,`features`,`cost`,`is_popular`)
VALUES
('plan_forgeshift_starter','forgeshift','Starter','$0','/mo','Basic migration tools for small teams.',JSON_ARRAY('Up to 10 migrations','Basic UI access','Email support'),0,0),
('plan_forgeshift_enterprise_plus','forgeshift','Enterprise - Plus (SaaS & OPDK)','Contact Sales',NULL,'Comprehensive migration support.',JSON_ARRAY('100% automated migration & cutover with ZERO DOWNTIME','Unlimited Proxy & Resources migration','Unlimited User & Role Migration','Developer Portal Migration','Integrated inbuilt Proxy Editor with AI enabled','100% Customized product','Migration support Env to Env & Hybrid','Integrated Cloud Storage, Github, CICD, SSO','Integrated with Advance complience','Dedicated PS & migration team','Advanced Dashbord with Report and Alert','8*5 support + SLA','Contact sales : info@probestack.io'),0,0),
('plan_forgestudio_starter','forgestudio','Starter','$0','/month/user','Ideal for small API teams.',JSON_ARRAY('1 user, 2 API (public only), 1 Project','OpenAPI editor (YAML/JSON)','Visual OpenAPI designer','5 Contract Testing','API Linting','Interactive API documentation','OpenAPI + JSON Schema','Community support'),0,0),
('plan_forgestudio_enterprise','forgestudio','Enterprise','$29','/month/user','Advanced collaboration.',JSON_ARRAY('Included Starter Features','Private APIs & Projects','Collaboration (multi-user editing)','Cloning, Versioning & Governance rules','API style validation using Linting','Model Schema Mapping','CICD & Connectors integrations','Team access with 5 users','50 Contracts Testing','SDK / Advanced Linting','Email support'),29,1),
('plan_forgestudio_enterprise_plus','forgestudio','Enterprise - Plus (SaaS & OPDK)','Contact Sales',NULL,'Dedicated Enterprise for scale.',JSON_ARRAY('Includes Enterprise','Available both SaaS/Self Hosted','Unlimited users','Unlimited API Design','SSO (SAML/LDAP)','Organization, Project & Team management','Audit logs (compliance)','Role-based access control','Advanced templates & governance','Specification Library','AI-native tools (trend): Generate APIs, CICD enabled from prompts, AI validation rules, AI security/compliance scanning, Auto-create OpenAPI specs from APIs, Auto-generate test cases','Contract/Functional Testing','Dedicated infrastructure','Advanced Dashboard','24/7 support'),0,0),
('plan_forgeq_starter','forgeq','Starter','$0','/month/user','Basic testing capabilities.',JSON_ARRAY('Standard API testing','API requests (REST, GraphQL)','Collections Testing','Environment variables','Basic testing scripts','Limited collaboration','Offline-first API testing','Monitoring','Email support'),0,0),
('plan_forgeq_enterprise','forgeq','Enterprise','$19','/month/user','Comprehensive API & MCP testing.',JSON_ARRAY('Includes Starter','API , MCP & Collections Testing','Web Application Testing','Projects & Team Managemnet','Mock servers','Git sync','CI/CD integration','Monitoring + automation','Email support'),19,1),
('plan_forgeq_enterprise_plus','forgeq','Enterprise - Plus (SaaS & OPDK)','Contact Sales',NULL,'Advanced API, UI, MCP & AI testing.',JSON_ARRAY('Includes Enterprise','Includes Enterprise','SSO & Role-based access','Enterprise sync','Audit logs','Unlimited runs','Load /PerformanceTesting','Monitoring + analytics','API stress testing','API governance','API Security Testing','AI debugging + auto-fix','Integrated  all AI models','AI generate Testcase','AI updates tests automatically','Test data generation','Zero manual test writing','Simulate failures','Latency injection','LLM Model Testing (Coming Soon)','Agentic AI Testing (Coming Soon)','Record & replay testing (Coming Soon)','24/7 support','Contact sales : info@probestack.io'),0,0),
('plan_forgesphere_starter','forgesphere','Starter','$19','/month/user','Basic API Lifecycle.',JSON_ARRAY('Up to 50 Microservice & APIs Proxies','Java Springboot API Generation, View & Edit','Python API Generation, View & Edit','NodeJS API Generation, View & Edit','APIGEE Proxy Generation, View & Edit','API Deploy to GCP ','API Design','Mock service Generation','Contract Testing','TestCase generation','Integrated CICD for API and Proxy Deployment','Automation Functional Testing','Automation Unit Testing','Security Testing','Support Artifctory Registry ','Support Github Action ','Integrated with Cloud connectors AWS, GCP , Azure , Github, Action, Cloud Storage, Apigee, API Linting Connectors ','Integrated with SCM connectors Github, Github Action, API Linting Connectors ','Integrated with Cloud Storage connectors GCS, S3, API Linting Connectors ','Integrated with API Gateway connectors Apigee Connectors ','15-day log retention','Standard dashboards','Email Support'),19,0),
('plan_forgesphere_enterprise','forgesphere','Enterprise','$49','/month/user','Advanced API Lifecycle.',JSON_ARRAY('Includes Starter','Java Springboot API Generation, View, Edit, Clone & Versioning','Python API Generation, View, Edit, Clone & Versioning','NodeJS API Generation, View, Edit, Clone & Versioning','APIGEE Proxy Generation, View, Edit, Clone & Versioning','KONG Service Generation, View, Edit, Clone & Versioning','MULESOFT Api Generation, View, Edit, Clone & Versioning','API Deploy to GCP, Azure & AWS ','API Proxy Deploy to Apigee, Kong & Mulesoft','API Design','Mock service Generation','Contract Testing','TestCase generation','Integrated CICD for API and Proxy Deployment','Automation Functional Testing','Automation Unit Testing','Security Testing','Support Artifctory Registry ','Support Github Action ','API Governance ','Integrated CICD for API and Proxy Deployment','Integrated with Cloud connectors AWS, GCP , Azure Connectors ','Integrated with SCM connectors Github, Github Action, API Linting Connectors ','Integrated with Cloud Storage connectors GCS, S3, API Linting Connectors ','Integrated with API Gateway connectors Apigee, Kong , Mulesoft Connectors ','30-day log retention','Standard dashboards','Priority support'),49,1),
('plan_forgesphere_enterprise_plus','forgesphere','Enterprise - Plus (SaaS & OPDK)','Contact Sales',NULL,'Unlimited scaled API Lifecycle.',JSON_ARRAY('Includes Enterprise ','SSO & Role-based access','MCP Generation, View, Edit, Clone , Versioning & Deprecation','MCP Expose to Apigee MCP Gateway','Audit logs','Java Springboot API Generation, View, Edit, Clone , Versioning & Deprecation','Python API Generation, View, Edit, Clone , Versioning & Deprecation','NodeJS API Generation, View, Edit, Clone , Versioning & Deprecation','APIGEE Proxy Generation, View, Edit, Clone , Versioning & Deprecation','KONG Service Generation, View, Edit, Clone , Versioning & Deprecation','MULESOFT Api Generation, View, Edit, Clone , Versioning & Deprecation','Apigee Proxy Editor, Debug and Trace ','Kong Service Editor, Debug and Trace','One Click for higher environmnet Deployment','API Advance Governance ','AI-native tools (trend): Generate Microservice , Proxy & CICD enabled from prompts, AI validation rules, AI security/compliance scanning, Auto-create OpenAPI specs from APIs,Auto-generate test cases','Advanced Dashboard','Advanced Analytics','8*5 Support','Contact sales : info@probestack.io'),0,0),
('plan_forgeai_starter','forgeai','Starter','$2,500','/month','Advanced AI traffic routing & observability.',JSON_ARRAY('Up to 200K API Calls/mo','Advanced AI Gateway features','Create AI Proxies','Create MCP Proxies','Transform API to MCP','OpenAI, Anthropic, Google LLM Models','Multi-provider LLM routing with 3 Envs','Gateway Dashboard with 30days log.','Rate limiting & throttling','Prompt Injection Detection','Jailbreak Detection','Toxic Content / RAI Filters','PII Detection (Sensitive Data)','Sensitive Data Protection','Model Armor (GCP) or Amazon Bedrock or Azure AI','API key management','AI Developer Portal','Request/response logging','Audit log','Email support'),2500,0),
('plan_forgeai_enterprise','forgeai','Enterprise','$8,500','/month','Advanced AI traffic routing & observability.',JSON_ARRAY('Up to 3M API Calls/mo & SSO / SAML integration','Create AI Proxies','Create MCP Proxies','Transform API to MCP','OpenAI, Anthropic, Google LLM Models','Multi-provider LLM routing with 3 Envs','Gateway Dashboard with 30days log.','Rate limiting & throttling','Caching & semantics','Prompt Injection Detection','Jailbreak Detection','Toxic Content / RAI Filters','PII Detection (Sensitive Data)','Sensitive Data Protection','Model Armor (GCP) or Amazon Bedrock or Azure AI','API key management','AI Developer Portal','Request/response logging','Audit log','Cost allocation & per-team budgets','Latency & token analytics dashboard','Priority support'),8500,1),
('plan_forgeai_enterprise_plus','forgeai','Enterprise - Plus (SaaS & OPDK)','Contact Sales',NULL,'Advanced AI traffic routing & observability.',JSON_ARRAY('Unlimited tokens','Dedicated Infrastructure','Create AI Proxies','Create MCP Proxies','Transform API to MCP','OpenAI, Anthropic, Google LLM Models','Multi-provider LLM routing with 3 Envs','Gateway Dashboard with 30days log.','Rate limiting & throttling','Caching & semantics','Prompt Injection Detection','Jailbreak Detection','Toxic Content / RAI Filters','PII Detection (Sensitive Data)','Sensitive Data Protection','Model Armor (GCP) or Amazon Bedrock or Azure AI','API key management','AI Developer Portal','Request/response logging','Audit log','Cost allocation & per-team budgets','Latency & token analytics dashboard','Custom model adapters & self-hosted LLMs','99.99% uptime SLA + dedicated support','Fine-grained RBAC per team/model','Private deployment (air-gapped available)','Contact sales : info@probestack.io','24/7 support'),0,0),
('plan_agentic_ai_starter','agentic_ai','Starter','$49','/month/user','Explore autonomous agents.',JSON_ARRAY('Up to 10 autonomous agents','Basic RAG','Email support'),49,0),
('plan_agentic_ai_enterprise','agentic_ai','Enterprise','$999','/month/user','Explore autonomous agents.',JSON_ARRAY('Up to 10 autonomous agents','Basic RAG','Email support'),999,0),
('plan_agentic_ai_enterprise_plus','agentic_ai','Enterprise - Plus (SaaS & OPDK)','Contact Sales','/ 200 Users','Unlimited agentic workflows.',JSON_ARRAY('Unlimited Agents creation','Agent Inventory, RAG, Multi Model','24/7 support + SLA guarantee'),0,1);

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
FROM `tmp_pricing_plan_catalog` pc
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
  `is_popular` = VALUES(`is_popular`),
  `is_active` = VALUES(`is_active`);

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
JOIN `tmp_pricing_plan_catalog` pc ON pc.`id` = pl.`id`
ON DUPLICATE KEY UPDATE
  `plan_id` = VALUES(`plan_id`),
  `name` = VALUES(`name`),
  `description` = VALUES(`description`),
  `price_monthly` = VALUES(`price_monthly`),
  `price_yearly` = VALUES(`price_yearly`),
  `display_order` = VALUES(`display_order`),
  `is_active` = VALUES(`is_active`);

SELECT 'synced_public_pricing_products' AS `check_name`, COUNT(*) AS `count`
FROM `products`
WHERE `key` IN ('forgeshift','forgestudio','forgeq','forgesphere','forgeai','agentic_ai');

SELECT 'synced_public_pricing_plans' AS `check_name`, COUNT(*) AS `count`
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

DROP TEMPORARY TABLE IF EXISTS `tmp_pricing_plan_catalog`;
