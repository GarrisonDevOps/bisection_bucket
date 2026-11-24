# frozen_string_literal: true

module EE
  module Clusters
    module Agent
      extend ActiveSupport::Concern

      prepended do
        has_one :agent_url_configuration, class_name: 'Clusters::Agents::UrlConfiguration', inverse_of: :agent

        has_many :vulnerability_reads, class_name: 'Vulnerabilities::Read', foreign_key: :casted_cluster_agent_id

        has_many :workspaces,
          class_name: 'RemoteDevelopment::Workspace',
          foreign_key: 'cluster_agent_id',
          inverse_of: :agent

        # WARNING: Do not use this `unversioned_latest_workspaces_agent_config`
        # association unless you are positive that is what you want to do!
        #
        # If you are attempting to get the associated WorkspacesAgentConfig
        # for a workspace, you should instead be directly using the
        # `workspace.workspaces_agent_config` method, which will return the proper
        # version of the config which is associated with that specific workspace.
        #
        # For more explanation, see:
        # https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/lib/remote_development/README.md#workspaces_agent_configs-versioning
        has_one :unversioned_latest_workspaces_agent_config,
          class_name: 'RemoteDevelopment::WorkspacesAgentConfig',
          inverse_of: :agent,
          foreign_key: :cluster_agent_id

        has_many :namespace_cluster_agent_mappings,
          class_name: 'RemoteDevelopment::NamespaceClusterAgentMapping',
          inverse_of: :agent,
          foreign_key: 'cluster_agent_id'

        has_one :organization_cluster_agent_mapping,
          class_name: 'RemoteDevelopment::OrganizationClusterAgentMapping',
          inverse_of: :agent,
          foreign_key: 'cluster_agent_id'

        scope :for_organizations, ->(organization_ids) {
          where(project_id: ::Project.in_organization(organization_ids).select('id'))
        }

        def self.ids_for_organizations(ids, organization_ids)
          # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the caller's own
          # ids argument (for example, one rollout's distinct cluster_agent_ids), not user input
          for_organizations(organization_ids).where(id: ids).pluck(:id)
          # rubocop:enable Database/AvoidUsingPluckWithoutLimit
        end

        scope :with_workspaces_agent_config, -> {
                                               joins(:unversioned_latest_workspaces_agent_config)
                                             }
        scope :without_workspaces_agent_config, -> do
          includes(:unversioned_latest_workspaces_agent_config).where(
            unversioned_latest_workspaces_agent_config: { cluster_agent_id: nil }
          )
        end
        scope :with_remote_development_enabled, -> do
          with_workspaces_agent_config.where(
            unversioned_latest_workspaces_agent_config: { enabled: true }
          )
        end

        def resource_management_enabled?
          project.licensed_feature_available?(:agent_managed_resources)
        end
      end
    end
  end
end
