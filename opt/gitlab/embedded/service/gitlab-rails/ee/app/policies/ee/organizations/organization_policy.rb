# frozen_string_literal: true

module EE
  module Organizations
    module OrganizationPolicy
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        include RemoteDevelopment::OrganizationPolicy
        include ::Analytics::CustomDashboards::OrganizationPolicy
        include ::Ai::Catalog::McpServers::OrganizationPolicy
        # Grants :access_advanced_vulnerability_management so the organization-level security
        # dashboard can resolve metrics from Elasticsearch, matching how GroupPolicy and
        # ProjectPolicy gate the same ability.
        include ::Vulnerabilities::AdvancedVulnerabilityManagementPolicy

        condition(:dependency_scanning_enabled) do
          License.feature_available?(:dependency_scanning)
        end

        condition(:license_scanning_enabled) do
          License.feature_available?(:license_scanning)
        end

        condition(:configurable_work_item_types_enabled) do
          License.feature_available?(:configurable_work_item_types)
        end

        condition(:security_dashboard_enabled) do
          License.feature_available?(:security_dashboard)
        end

        condition(:ai_analytics_enabled, scope: :global) do
          License.feature_available?(:ai_analytics)
        end

        condition(:contribution_analytics_enabled, scope: :global) do
          License.feature_available?(:contribution_analytics)
        end

        condition(:cycle_analytics_enabled, scope: :global) do
          License.feature_available?(:cycle_analytics_for_groups)
        end

        condition(:dora4_analytics_enabled, scope: :global) do
          License.feature_available?(:dora4_analytics)
        end

        condition(:compliance_dashboard_enabled, scope: :global) do
          License.feature_available?(:group_level_compliance_dashboard)
        end

        condition(:organization_billing_active, scope: :subject) do
          ::GitlabSubscriptions::OrganizationBilling.active?(@subject)
        end

        # Gate for organization-level analytics aggregation endpoints. Licensing is
        # not checked here: the per-group abilities checked in the resolvers
        # (for example :read_pro_ai_analytics) enforce it per engine.
        rule { admin | organization_user }.enable :read_organization_analytics

        # Organization-wide aggregation of these analytics needs every namespace to belong to
        # the organization, which holds only on instances with one organization.
        rule { is_gitlab_com }.policy do
          prevent :read_agent_artifacts
          prevent :read_ci_cd_analytics
          prevent :read_contribution_analytics
          prevent :read_cycle_analytics
          prevent :read_dora4_analytics
          prevent :read_pro_ai_analytics
        end

        rule { ~ai_analytics_enabled }.prevent :read_pro_ai_analytics
        rule { ~compliance_dashboard_enabled }.prevent :read_agent_artifacts
        rule { ~contribution_analytics_enabled }.prevent :read_contribution_analytics
        rule { ~cycle_analytics_enabled }.prevent :read_cycle_analytics
        rule { ~dora4_analytics_enabled }.prevent :read_dora4_analytics

        rule { (admin | organization_user) & dependency_scanning_enabled }.enable :read_dependency
        rule { (admin | organization_user) & license_scanning_enabled }.enable :read_licenses

        # Organization-level security dashboard (work in progress, gated at the resolver by the
        # `organization_security_dashboard` feature flag). Role gating is intentionally
        # conservative (owners/admins only) and should be refined with the security team.
        rule { (admin | organization_owner) & security_dashboard_enabled }.enable :read_security_resource

        rule { auditor }.policy do
          enable(*::Authz::Role.get(:auditor).permissions(:organization))
        end

        # admin receives these through the admin role definition
        # (config/authz/roles/admin.yml, organization scope).
        rule { organization_owner }.policy do
          enable :create_govern_policy
          enable :read_govern_policy
          enable :update_govern_policy
          enable :delete_govern_policy
        end

        rule { admin | organization_owner }.policy do
          enable :read_work_item_setting
          enable :create_work_item_type
          enable :update_work_item_type
          enable :update_work_item_setting
        end

        rule { ~organization_billing_active }.policy do
          prevent :read_subscription_usage
          prevent :update_subscription_usage_cap
        end

        rule { ~configurable_work_item_types_enabled }.policy do
          prevent :create_work_item_type
          prevent :update_work_item_type
          prevent :read_work_item_setting
          prevent :update_work_item_setting
        end

        rule { admin | organization_owner }.policy do
          enable :read_cd_application
          enable :create_cd_application
          enable :update_cd_application
          enable :read_cd_environment
          enable :create_cd_environment
          enable :update_cd_environment
          enable :create_cd_service
          enable :update_cd_service
          enable :create_cd_artifact_source
          enable :create_cd_version_set
          enable :create_cd_application_flow_definition
          enable :create_cd_rollout
          enable :resolve_cd_rollout_gate
          enable :create_cd_application_link
          enable :update_cd_application_link
          enable :delete_cd_application_link
          enable :read_cd_service
          enable :read_cd_artifact_source
          enable :read_cd_version_set
          enable :read_cd_application_flow_definition
          enable :read_cd_rollout
          enable :read_cd_application_link
        end
      end
    end
  end
end
