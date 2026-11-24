# frozen_string_literal: true

module EE
  module Organizations
    module Organization
      extend ActiveSupport::Concern

      prepended do
        include ::Ai::FoundationalAgentsStatusable
        include ::ArtifactRegistry::CachesClient

        has_many :active_projects,
          -> { non_archived },
          class_name: 'Project',
          inverse_of: :organization
        has_many :add_on_purchases,
          class_name: '::GitlabSubscriptions::AddOnPurchase',
          inverse_of: :organization
        has_many :seat_assignments,
          class_name: '::GitlabSubscriptions::SeatAssignment',
          inverse_of: :organization
        has_many :user_add_on_assignments,
          class_name: '::GitlabSubscriptions::UserAddOnAssignment',
          inverse_of: :organization
        has_many :vulnerability_exports, class_name: 'Vulnerabilities::Export'
        has_many :sbom_sources, class_name: 'Sbom::Source'
        has_many :sbom_source_packages, class_name: 'Sbom::SourcePackage'
        has_many :sbom_components, class_name: 'Sbom::Component'
        has_many :sbom_component_versions, class_name: 'Sbom::ComponentVersion'
        has_many :organization_cluster_agent_mappings,
          class_name: 'RemoteDevelopment::OrganizationClusterAgentMapping',
          inverse_of: :organization
        has_many :mapped_agents, through: :organization_cluster_agent_mappings, source: :agent

        has_many :custom_dashboards,
          class_name: 'Analytics::CustomDashboards::Dashboard',
          foreign_key: :organization_id,
          inverse_of: :organization

        has_many :foundational_agents_status_records,
          class_name: 'Ai::OrganizationFoundationalAgentStatus',
          inverse_of: :organization

        has_many :ai_user_memories,
          class_name: 'Ai::OrganizationUserMemory',
          inverse_of: :organization

        has_one :artifact_registry_namespace_mapping,
          class_name: 'ArtifactRegistry::NamespaceMapping',
          inverse_of: :organization

        has_one :organization_gitlab_subscription,
          class_name: 'Organizations::OrganizationGitlabSubscription',
          inverse_of: :organization
        has_one :gitlab_subscription, through: :organization_gitlab_subscription
        has_one :billing_namespace, through: :gitlab_subscription, source: :namespace

        def foundational_agents_default_enabled
          ::Ai::Setting.for_organization_read_only(self).foundational_agents_default_enabled
        end

        # Activation is the mapping row existing. Handle and status come from a call that
        # can fail, and folding it in would report an outage as a never-activated
        # organization; see https://gitlab.com/gitlab-org/gitlab/-/work_items/608391.
        def artifact_registry_activated?
          artifact_registry_namespace_mapping.present?
        end

        def artifact_registry_resolved_slug
          registry = artifact_registry_namespace_mapping&.registry

          registry.slug if registry&.resolved?
        end

        def policy_store_experiment_available?
          ::Feature.enabled?(:security_policies_v2, self) &&
            ::Gitlab::CurrentSettings.policy_store_experiment_enabled? &&
            ::License.feature_available?(:security_orchestration_policies)
        end

        def policy_store_experiment_active?
          policy_store_experiment_available? && policy_store_experiment_enabled?
        end

        def policy_store_experiment_enabled?
          settings&.policy_store_experiment_enabled == true
        end
      end
    end
  end
end
