# frozen_string_literal: true

module EE
  module ApplicationSettings
    module UpdateService
      extend ::Gitlab::Utils::Override
      extend ActiveSupport::Concern
      include ::Gitlab::InternalEventsTracking
      include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils

      DUO_AGENT_PLATFORM_CHILD_SETTINGS = %i[
        duo_remote_flows
        duo_foundational_flows
        duo_scheduled_automations
        duo_custom_agents
        duo_custom_flows
        duo_external_agents
      ].freeze

      override :execute
      def execute
        # Repository size limit comes as MB from the view
        limit = params.delete(:repository_size_limit)
        application_setting.repository_size_limit = ::Gitlab::Utils.try_megabytes_to_bytes(limit) if limit

        if params[:maintenance_mode] == false || params[:maintenance_mode_message] == ''
          params[:maintenance_mode_message] = nil
        end

        elasticsearch_shards = params.delete(:elasticsearch_shards)
        elasticsearch_replicas = params.delete(:elasticsearch_replicas)

        elasticsearch_namespace_ids = params.delete(:elasticsearch_namespace_ids)
        elasticsearch_project_ids = params.delete(:elasticsearch_project_ids)

        params[:enable_member_promotion_management] = get_enable_member_promotion_management

        filter_auto_duo_code_review_param
        filter_duo_code_review_decision_params
        filter_duo_code_review_depth_params
        cascade_disable_duo_agent_platform_child_settings

        default_organization, previous_statuses, default_enabled, new_statuses = prepare_organization_settings
        handle_organization_settings(default_organization, new_statuses)

        duo_namespace_access_rules = params[:duo_namespace_access_rules]
        handle_duo_namespace_access_rules

        if result = super
          find_or_create_elasticsearch_index if params.keys.any? { |key| key.to_s.start_with?('elasticsearch') }
          update_elasticsearch_containers(ElasticsearchIndexedNamespace, elasticsearch_namespace_ids)
          update_elasticsearch_containers(ElasticsearchIndexedProject, elasticsearch_project_ids)
          update_elasticsearch_index_settings(number_of_replicas: elasticsearch_replicas,
            number_of_shards: elasticsearch_shards)

          cascade_duo_features_settings
          cascade_built_in_project_templates_enabled_setting

          audit_duo_namespace_access_rules_update(duo_namespace_access_rules) if duo_namespace_access_rules

          track_deletion_protection_toggle

          # There are cases when current user is passed as nil like in elastic.rake
          # we should not log audit events in such cases
          if current_user
            log_audit_events
            audit_organization_foundational_agent_status_changes(default_organization, new_statuses,
              previous_statuses, default_enabled)
          end

        end

        result
      end

      def prepare_organization_settings
        return [nil, nil, nil, nil] unless params.has_key?(:foundational_agents_statuses)

        default_organization = ::Organizations::Organization.default_organization
        previous_statuses = default_organization.foundational_agents_statuses
        default_enabled = default_organization.foundational_agents_default_enabled
        new_statuses = params.delete(:foundational_agents_statuses)

        [default_organization, previous_statuses, default_enabled, new_statuses]
      end

      def handle_organization_settings(default_organization, new_statuses)
        return unless default_organization

        default_organization.update(foundational_agents_statuses: new_statuses)

        return unless default_organization.errors.any?

        application_setting
          .errors
          .add(:foundational_agents_statuses, default_organization.errors.full_messages.join(', '))
      end

      def handle_duo_namespace_access_rules
        return unless params.has_key?(:duo_namespace_access_rules)

        duo_namespace_access_rules = params.delete(:duo_namespace_access_rules)

        ::Ai::FeatureAccessRule.duo_namespace_access_rules = duo_namespace_access_rules
      rescue ArgumentError, ActiveRecord::RecordInvalid => e
        application_setting.errors.add(:duo_namespace_access_rules, e.message)
      end

      def update_elasticsearch_containers(klass, new_container_ids)
        return unless application_setting.elasticsearch_limit_indexing?
        return if new_container_ids.nil?

        new_container_ids = new_container_ids.split(',').map(&:to_i) unless new_container_ids.is_a?(Array)

        # Destroy any containers that have been removed. This runs callbacks, etc
        klass.remove_all(except: new_container_ids)

        # Disregard any duplicates that are already present
        new_container_ids -= klass.target_ids

        # Add new containers
        new_container_ids.each { |id| klass.create!(klass.target_attr_name => id) }
      end

      def update_elasticsearch_index_settings(number_of_replicas:, number_of_shards:)
        return if number_of_replicas.nil? && number_of_shards.nil?

        if number_of_shards&.respond_to?(:to_h)
          number_of_shards.to_h.each do |index_name, shards|
            replicas = number_of_replicas[index_name]

            next if shards.blank? || replicas.blank?

            Elastic::IndexSetting[index_name].update!(
              number_of_replicas: replicas.to_i,
              number_of_shards: shards.to_i
            )
          end
        else
          # This method still receives non-hash values from API
          Elastic::IndexSetting.every_alias do |setting|
            setting.update!(
              number_of_replicas: number_of_replicas || setting.number_of_replicas,
              number_of_shards: number_of_shards || setting.number_of_shards
            )
          end
        end
      end

      private

      def filter_auto_duo_code_review_param
        return if ::Gitlab::Duo::CodeReview.automatic_review_available?(application_setting)

        params.delete(:auto_duo_code_review_enabled)
        params.delete(:auto_duo_code_review_on_push_enabled)
      end

      def filter_duo_code_review_depth_params
        return if ::Gitlab::Duo::CodeReview.depth_settings_available?(application_setting)

        params.delete(:duo_code_review_depth_allowed)
        params.delete(:duo_code_review_default_depth)
      end

      def filter_duo_code_review_decision_params
        return if ::Gitlab::Duo::CodeReview.decisions_settings_available?(application_setting)

        params.delete(:duo_code_review_decisions_enabled)
      end

      # Mirrors the admin UI, which disables all child settings when DAP is turned off.
      # Conflicting child params are dropped so the result doesn't depend on assignment order.
      def cascade_disable_duo_agent_platform_child_settings
        return unless params.key?(:duo_agent_platform_enabled)
        return unless ::Gitlab::Utils.to_boolean(params[:duo_agent_platform_enabled]) == false

        DUO_AGENT_PLATFORM_CHILD_SETTINGS.each do |setting|
          params.delete(:"#{setting}_enabled")
          params.delete(:"lock_#{setting}_enabled")
          params[:"#{setting}_availability"] = false
        end
      end

      def cascade_duo_features_settings
        previous_changes = application_setting.previous_changes
        cascading_ai_settings = [
          :duo_features_enabled,
          :lock_duo_features_enabled,
          :duo_remote_flows_enabled,
          :auto_duo_code_review_enabled,
          :duo_foundational_flows_enabled,
          :duo_scheduled_triggers_enabled,
          :duo_custom_agents_enabled,
          :duo_custom_flows_enabled,
          :duo_external_agents_enabled,
          :ai_audit_events_storage_enabled,
          :ai_governance_enabled,
          :duo_auto_mode_enabled,
          :ai_agent_governance_enforcement,
          :duo_code_review_depth_allowed,
          :duo_code_review_default_depth
        ]

        # Collect all changed AI settings and their values
        changed_ai_settings = cascading_ai_settings.filter_map do |setting|
          [setting.to_s, application_setting.attributes[setting.to_s]] if previous_changes.include?(setting)
        end.to_h
        return if changed_ai_settings.empty?

        ::AppConfig::CascadeDuoSettingsWorker.perform_async(changed_ai_settings)
      end

      def cascade_built_in_project_templates_enabled_setting
        previous_changes = application_setting.previous_changes
        return unless previous_changes.include?(:built_in_project_templates_enabled)

        ::AppConfig::CascadeBuiltInProjectTemplatesEnabledWorker.perform_async(
          application_setting.built_in_project_templates_enabled
        )
      end

      def should_auto_approve_blocked_users?
        super || user_cap_increased?
      end

      def log_audit_events
        ::AppConfig::ApplicationSettingChangesAuditor.new(current_user, application_setting).execute
      end

      def user_cap_increased?
        return false unless application_setting.previous_changes.key?(:new_user_signups_cap)

        previous_user_cap, current_user_cap = application_setting.previous_changes[:new_user_signups_cap]

        return false if previous_user_cap.nil?

        current_user_cap.nil? || current_user_cap > previous_user_cap
      end

      def find_or_create_elasticsearch_index
        # The order of checks is important. We should not attempt to create a new index
        # unless elasticsearch_indexing is enabled
        return unless application_setting.elasticsearch_indexing

        elasticsearch_helper.create_empty_index(options: { skip_if_exists: true })
        elasticsearch_helper.create_standalone_indices(options: { skip_if_exists: true })

        unless elasticsearch_helper.migrations_index_exists?
          elasticsearch_helper.create_migrations_index
          ::Elastic::DataMigrationService.mark_all_as_completed!
        end
      rescue ::Gitlab::Search::Client::ConnectionError, ::Gitlab::Search::Client::AuthorizationError,
        ::Elasticsearch::Transport::Transport::Error => e
        log_error(e)
      end

      def elasticsearch_helper
        @elasticsearch_helper ||= ::Search::Elastic::Helper.new(client: elasticsearch_client)
      end

      def elasticsearch_client
        ::Search::Elastic::Client.build(application_setting.elasticsearch_config)
      end

      def get_enable_member_promotion_management
        param_value = ActiveRecord::Type::Boolean.new.cast(params.delete(:enable_member_promotion_management))

        return application_setting.enable_member_promotion_management if param_value.nil?
        return false unless member_promotion_management_feature_available?
        return true if param_value == false && pending_member_approvals?

        param_value
      end

      def pending_member_approvals?
        ::GitlabSubscriptions::MemberManagement::SelfManaged::MaxAccessLevelMemberApprovalsFinder
          .new(current_user).execute.any?
      end

      def audit_duo_namespace_access_rules_update(rules)
        ::Ai::FeatureAccessRuleAuditor.new(
          current_user: current_user,
          rules: rules,
          scope: ::Gitlab::Audit::InstanceScope.new
        ).execute
      end

      def audit_organization_foundational_agent_status_changes(
        default_organization, new_statuses,
        previous_statuses, default_enabled)
        return unless default_organization

        ::Ai::FoundationalAgentStatusAuditor.new(
          current_user: current_user,
          scope: ::Gitlab::Audit::InstanceScope.new,
          previous_statuses: previous_statuses,
          new_statuses: new_statuses,
          default_enabled: default_enabled
        ).execute
      end

      def track_deletion_protection_toggle
        return unless application_setting.previous_changes.key?(:default_project_deletion_protection)

        track_internal_event(
          'toggle_deletion_protection_on_admin_area',
          user: current_user,
          label: application_setting.default_project_deletion_protection.to_s
        )
      end
    end
  end
end
