# frozen_string_literal: true

module Ai
  class CascadeDuoSettingsService
    BATCH_SIZE = 100
    DUO_SETTINGS = %w[
      duo_features_enabled
      lock_duo_features_enabled
      duo_remote_flows_enabled
      auto_duo_code_review_enabled
      auto_duo_code_review_on_push_enabled
      duo_foundational_flows_enabled
      duo_scheduled_triggers_enabled
      duo_custom_agents_enabled
      duo_custom_flows_enabled
      duo_external_agents_enabled
      tool_approval_for_session_enabled
      ai_audit_events_storage_enabled
      ai_governance_enabled
      ai_agent_governance_enforcement
      enabled_foundational_flows
      duo_auto_mode_enabled
      duo_code_review_depth_allowed
      duo_code_review_default_depth
    ].freeze

    GROUP_ONLY_SETTINGS = %w[duo_custom_agents_enabled duo_custom_flows_enabled duo_external_agents_enabled].freeze

    # Settings that exist on namespace_settings but not on project_settings
    NAMESPACE_ONLY_SETTINGS = %w[lock_duo_features_enabled].freeze

    def initialize(setting_attributes, current_user: nil)
      @setting_attributes = setting_attributes.stringify_keys
      @flow_ids = @setting_attributes.delete('enabled_foundational_flows')
      @current_user = current_user

      check_setting_attributes!
      reset_duo_code_review_default_depth
    end

    def cascade_for_group(group)
      return if @setting_attributes.empty? && @flow_ids.nil?

      update_subgroups(group) if @setting_attributes.any?
      update_projects(group) if @setting_attributes.any?
      cascade_flow_selection(group) unless @flow_ids.nil?
      schedule_foundational_flows_sync(group) if foundational_flows_changed?
    end

    def cascade_for_instance
      return if @setting_attributes.empty?

      project_attributes = @setting_attributes.except(*GROUP_ONLY_SETTINGS, *NAMESPACE_ONLY_SETTINGS)
      if project_attributes.any?
        ProjectSetting.each_batch(of: 25000) do |batch|
          batch.update_all(project_attributes)
        end
      end

      ::NamespaceSetting.each_batch(of: 25000) do |batch|
        batch.update_all(@setting_attributes)
      end
    end

    private

    attr_reader :setting_attributes, :flow_ids, :current_user

    # update_all skips the model callback that resets Standard when Standard reviews are not allowed.
    def reset_duo_code_review_default_depth
      return unless @setting_attributes.key?('duo_code_review_depth_allowed')
      return unless ActiveModel::Type::Boolean.new.cast(@setting_attributes['duo_code_review_depth_allowed']) == false

      @setting_attributes['duo_code_review_default_depth'] = ::Gitlab::Duo::CodeReview::LITE_DEPTH
    end

    def check_setting_attributes!
      return if @setting_attributes.keys.all? { |key| DUO_SETTINGS.include?(key) }

      raise ArgumentError,
        "Invalid key in #{@setting_attributes}. Only the following Duo Settings can cascade: #{DUO_SETTINGS}"
    end

    def namespace_iterator(group)
      cursor = { current_id: group.id, depth: [group.id] }
      Gitlab::Database::NamespaceEachBatch.new(namespace_class: Group, cursor: cursor)
    end

    def project_namespace_iterator(group)
      cursor = { current_id: group.id, depth: [group.id] }
      Gitlab::Database::NamespaceEachBatch.new(namespace_class: Namespaces::ProjectNamespace, cursor: cursor)
    end

    def update_subgroups(group)
      namespace_iterator(group).each_batch(of: BATCH_SIZE) do |namespace_ids|
        ::NamespaceSetting.for_namespaces(namespace_ids)
                          .update_all(@setting_attributes)
      end
    end

    def update_projects(group)
      project_attributes = @setting_attributes.except(*GROUP_ONLY_SETTINGS, *NAMESPACE_ONLY_SETTINGS)
      return if project_attributes.empty?

      project_namespace_iterator(group).each_batch(of: BATCH_SIZE) do |project_namespace_ids|
        project_ids = Project.by_project_namespace(project_namespace_ids).select(:id)
        ProjectSetting.for_projects(project_ids).update_all(project_attributes)
      end
    end

    def cascade_flow_selection(group)
      target_references = @flow_ids || []
      target_ids = convert_flow_references_to_ids(target_references)

      group.sync_enabled_foundational_flows!(target_ids)

      namespace_iterator(group).each_batch(of: BATCH_SIZE) do |namespace_ids|
        Group.id_in(namespace_ids).id_not_in(group.id).find_each do |descendant_group|
          descendant_group.sync_enabled_foundational_flows!(target_ids)
        end
      end

      project_namespace_iterator(group).each_batch(of: BATCH_SIZE) do |project_namespace_ids|
        Project.by_project_namespace(project_namespace_ids).find_each do |project|
          project.sync_enabled_foundational_flows!(target_ids)
        end
      end
    end

    def foundational_flows_changed?
      @setting_attributes.key?('duo_foundational_flows_enabled') || !@flow_ids.nil?
    end

    def schedule_foundational_flows_sync(group)
      ::Ai::Catalog::Flows::CascadeSyncFoundationalFlowsWorker.perform_async(
        group.id,
        @current_user&.id,
        @flow_ids
      )
    end

    def convert_flow_references_to_ids(flow_references)
      return [] if flow_references.blank?

      reference_to_id_map = ::Ai::Catalog::Item.foundational_flow_ids_for_references(flow_references)
      flow_references.filter_map { |ref| reference_to_id_map[ref] }
    end
  end
end
