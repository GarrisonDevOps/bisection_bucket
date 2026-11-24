# frozen_string_literal: true

module RemoteDevelopment
  class WorkspacesAgentConfig < ApplicationRecord
    # NOTE: See the following comment for the reasoning behind the `Workspaces` prefix of this table/model:
    #       https://gitlab.com/gitlab-org/gitlab/-/issues/410045#note_1385602915

    include Sortable
    include SafelyChangeColumnDefault

    columns_changing_default :dns_zone

    UNLIMITED_QUOTA = -1
    MIN_HOURS_BEFORE_TERMINATION = 1

    has_paper_trail versions: {
      class_name: 'RemoteDevelopment::WorkspacesAgentConfigVersion'
    }

    belongs_to :agent,
      class_name: 'Clusters::Agent', foreign_key: 'cluster_agent_id',
      inverse_of: :unversioned_latest_workspaces_agent_config

    # noinspection RailsParamDefResolve - https://handbook.gitlab.com/handbook/tools-and-tips/editors-and-ides/jetbrains-ides/tracked-jetbrains-issues/#ruby-31542
    has_many :workspaces, through: :agent, source: :workspaces

    validates :agent, presence: true
    validates :dns_zone, hostname: { allow_numeric_hostname: true }, if: :dns_zone_required?
    validates :enabled, inclusion: { in: [true, false] }

    validates :network_policy_egress,
      json_schema: { filename: 'workspaces_agent_configs_network_policy_egress', size_limit: 64.kilobytes }
    validates :network_policy_egress, 'remote_development/network_policy_egress': true
    validates :default_resources_per_workspace_container,
      json_schema: { filename: 'workspaces_agent_configs_workspace_container_resources', size_limit: 64.kilobytes }
    validates :default_resources_per_workspace_container, 'remote_development/workspace_container_resources': true
    validates :max_resources_per_workspace,
      json_schema: { filename: 'workspaces_agent_configs_workspace_container_resources', size_limit: 64.kilobytes }
    validates :max_resources_per_workspace, 'remote_development/workspace_container_resources': true
    validates :workspaces_quota, numericality: { only_integer: true, greater_than_or_equal_to: UNLIMITED_QUOTA }
    validates :workspaces_per_user_quota,
      numericality: { only_integer: true, greater_than_or_equal_to: UNLIMITED_QUOTA }
    validates :allow_privilege_escalation, inclusion: { in: [true, false] }
    validates :use_kubernetes_user_namespaces, inclusion: { in: [true, false] }
    validates :default_runtime_class, 'remote_development/default_runtime_class': true
    validates :shared_namespace, 'remote_development/shared_namespace': true
    validates :annotations, 'remote_development/annotations': true
    validates :labels, 'remote_development/labels': true
    validates :gitlab_workspaces_proxy_http_enabled, inclusion: { in: [true, false] }
    validates :gitlab_workspaces_proxy_ssh_enabled, inclusion: { in: [true, false] }

    validates :image_pull_secrets,
      json_schema: {
        filename: 'workspaces_agent_configs_image_pull_secrets', detail_errors: true, size_limit: 64.kilobytes
      }
    validates :image_pull_secrets, 'remote_development/image_pull_secrets': true

    validates :max_active_hours_before_stop,
      numericality: {
        only_integer: true, greater_than_or_equal_to: 1,
        less_than_or_equal_to: WorkspaceOperations::MaxHoursBeforeTermination::MAX_HOURS_BEFORE_TERMINATION
      }
    validates :max_stopped_hours_before_termination,
      numericality: {
        only_integer: true, greater_than_or_equal_to: 1,
        less_than_or_equal_to: WorkspaceOperations::MaxHoursBeforeTermination::MAX_HOURS_BEFORE_TERMINATION
      }

    validate :validate_dns_zone_presence

    validate :validate_sum_of_delayed_termination_fields_does_not_exceed_max_hours_before_termination_limit

    validate :validate_allow_privilege_escalation

    validate :validate_image_pull_secrets_namespace

    validate :validate_max_resources_per_workspace

    scope :by_cluster_agent_ids, ->(ids) { where(cluster_agent_id: ids) }

    # The papertrail versioned records before the column gitlab_workspaces_proxy_http_enabled was introduced would not
    # have the field gitlab_workspaces_proxy_http_enabled present. Hence, we override the attribute reader to
    # consolidate/handle this in the model itself.
    def gitlab_workspaces_proxy_http_enabled
      return true if read_attribute(:gitlab_workspaces_proxy_http_enabled).nil?

      super
    end

    # The papertrail versioned records before the column gitlab_workspaces_proxy_ssh_enabled was introduced would not
    # have the field gitlab_workspaces_proxy_ssh_enabled present. Hence, we override the attribute reader to
    # consolidate/handle this in the model itself.
    def gitlab_workspaces_proxy_ssh_enabled
      return true if read_attribute(:gitlab_workspaces_proxy_ssh_enabled).nil?

      super
    end

    private

    # @return [Boolean]
    def dns_zone_required?
      gitlab_workspaces_proxy_http_enabled
    end

    # @return [void]
    def validate_dns_zone_presence
      return unless dns_zone_required?
      return if dns_zone.present?

      errors.add(:dns_zone, "can't be blank when gitlab_workspaces_proxy_http_enabled is true")
    end

    # @return [void]
    def validate_sum_of_delayed_termination_fields_does_not_exceed_max_hours_before_termination_limit
      max_hours_before_termination = WorkspaceOperations::MaxHoursBeforeTermination::MAX_HOURS_BEFORE_TERMINATION

      return if max_active_hours_before_stop + max_stopped_hours_before_termination <= max_hours_before_termination

      msg = _("Sum of max_active_hours_before_stop and max_stopped_hours_before_termination must not exceed " \
        "%{maximum_hours_before_termination} hours")
      errors.add(:base, format(msg, maximum_hours_before_termination: max_hours_before_termination))

      nil
    end

    # allow_privilege_escalation is allowed to be set to true only if
    # - either use_kubernetes_user_namespaces is true
    # - or default_runtime_class is set to a non-empty value
    # This ensures that unsafe usage of allow_privilege_escalation is not allowed.
    # @return [void]
    def validate_allow_privilege_escalation
      return unless allow_privilege_escalation
      return if use_kubernetes_user_namespaces || default_runtime_class.present?

      errors.add(:allow_privilege_escalation,
        _('can be true only if either use_kubernetes_user_namespaces is true or default_runtime_class is non-empty'))

      nil
    end

    # image_pull_secrets should all have the same namespace when shared_namespace is specified
    # The value should be the same as shared_namespace in such a case.
    # @return [void]
    def validate_image_pull_secrets_namespace
      return if shared_namespace.blank? || image_pull_secrets.blank?

      invalid_secrets = image_pull_secrets.select do |secret|
        secret['namespace'].present? && secret['namespace'] != shared_namespace
      end

      return if invalid_secrets.empty?

      errors.add(
        :image_pull_secrets,
        format(
          _("image_pull_secrets.namespace and shared_namespace must match if shared_namespace is specified")
        )
      )
      nil
    end

    # max_resources_per_workspace must be an empty hash if shared_namespace is specified
    # @return [void]
    def validate_max_resources_per_workspace
      return if shared_namespace.blank?
      return if max_resources_per_workspace.nil? || max_resources_per_workspace.empty?

      errors.add(
        :max_resources_per_workspace,
        format(
          _("max_resources_per_workspace must be an empty hash if shared_namespace is specified")
        )
      )
      nil
    end
  end
end
