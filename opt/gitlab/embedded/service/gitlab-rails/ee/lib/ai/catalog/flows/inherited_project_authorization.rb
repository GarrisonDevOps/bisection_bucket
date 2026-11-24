# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      # Authorizes materializing a root group's foundational-flow configuration in one project.
      #
      # The persisted project allowlist and its matching root-group consumer are the authority;
      # the initiating user is retained only as audit context. This object never creates or repairs
      # parent state, and service-boundary checks refresh the hierarchy before authorizing a write.
      #
      # Reloads narrow stale-state windows, but a project transfer can still commit between authorization and a write.
      # Transfer reconciliation, and which parts of this materialized path remain necessary, should be revisited with
      # proper group-level inheritance: https://gitlab.com/groups/gitlab-org/-/work_items/22487
      class InheritedProjectAuthorization
        SYSTEM_AUTHOR_NAME = '(System)'
        TRIGGER_DESCRIPTION = 'Foundational flow trigger for %s'

        def initialize(project:, item:, parent_consumer:, initiating_user: nil, initiating_user_id: nil)
          @project = project
          @item = item
          @parent_consumer = parent_consumer
          @initiating_user_id = initiating_user_id || initiating_user&.id
        end

        def allowed?
          failure_reason.nil?
        end

        def failure_reason
          project_failure_reason || item_failure_reason || parent_failure_reason
        end

        def project_failure_reason
          return :invalid_project unless valid_project?
          return :foundational_flows_disabled unless project.duo_foundational_flows_enabled
          return :foundational_flows_unavailable unless project.foundational_flows_available?
          return :catalog_provisioning_disabled unless ::Ai::Catalog.provisioning_available?(project)

          nil
        end

        def item_failure_reason
          return :item_not_foundational unless item&.foundational_flow?
          return :item_unavailable unless item.foundational_flow&.available_for?(root_group)
          return :organization_mismatch unless item.organization_id == project.organization_id
          return :item_not_enabled unless project.enabled_flow_catalog_item_ids.include?(item.id)

          nil
        end

        def parent_failure_reason
          return :parent_consumer_missing unless parent_consumer
          return :parent_consumer_mismatch unless matching_parent_consumer?
          return :parent_service_account_missing unless parent_consumer.active_service_account
          return :parent_service_account_mismatch unless matching_parent_service_account?

          nil
        end
        private :project_failure_reason, :item_failure_reason, :parent_failure_reason

        # Revalidates the exact consumer call against fresh hierarchy state.
        def item_consumer_failure_reason(container:, item:, parent_consumer:)
          refresh_failure_reason = refresh_hierarchy
          return refresh_failure_reason if refresh_failure_reason

          unless container == project && item == self.item && parent_consumer == self.parent_consumer
            return :authorization_context_mismatch
          end

          failure_reason
        end

        # Authorizes only a computed trigger for the exact inherited child consumer.
        def authorized_for_trigger?(project:, item_consumer:, params:)
          return false if refresh_hierarchy(item_consumer: item_consumer)

          allowed? &&
            project == self.project &&
            item_consumer&.project_id == self.project.id &&
            item_consumer.ai_catalog_item_id == item.id &&
            item_consumer.parent_item_consumer_id == parent_consumer.id &&
            matching_computed_trigger_params?(item_consumer, params)
        end

        def audit_author
          @audit_author ||= ::Gitlab::Audit::UnauthenticatedAuthor.new(name: SYSTEM_AUTHOR_NAME)
        end

        def audit_details
          {
            provisioning_source: 'inherited_project',
            initiating_user_id: initiating_user_id,
            parent_item_consumer_id: parent_consumer&.id,
            root_group_id: root_group&.id
          }.compact
        end

        private

        attr_reader :project, :item, :parent_consumer, :initiating_user_id

        def refresh_hierarchy(item_consumer: nil)
          @root_group = nil

          return :invalid_project unless reload_record(project)
          return :catalog_item_missing unless reload_record(item)
          return :parent_consumer_missing if parent_consumer && !reload_record(parent_consumer)
          return :item_consumer_missing if item_consumer&.persisted? && !reload_record(item_consumer)

          nil
        end

        def reload_record(record)
          record&.reload
        rescue ActiveRecord::RecordNotFound
          nil
        end

        def valid_project?
          project.is_a?(::Project) && project.persisted? && project.group.present?
        end

        def matching_parent_consumer?
          parent_consumer.persisted? &&
            parent_consumer.project_id.nil? &&
            parent_consumer.group_id == root_group.id &&
            parent_consumer.ai_catalog_item_id == item.id
        end

        def matching_parent_service_account?
          service_account = parent_consumer.active_service_account

          service_account&.service_account? && service_account.provisioned_by_group_id == root_group.id
        end

        def root_group
          @root_group ||= project&.root_ancestor
        end

        # Rejects manual accounts, arbitrary filters and descriptions, and extra attributes.
        # The only accepted filter is the flow definition's own default_trigger_filter.
        # Called only after allowed?, which already requires the flow definition.
        def matching_computed_trigger_params?(item_consumer, params)
          expected_keys = %i[ai_catalog_item_consumer_id description event_types filter]
          event_types = Array(params[:event_types])
          supported_event_types = Array(item.foundational_flow.triggers)

          item_consumer.persisted? &&
            params.except(*expected_keys).empty? &&
            params[:ai_catalog_item_consumer_id] == item_consumer.id &&
            params[:description] == format(TRIGGER_DESCRIPTION, item.name) &&
            event_types.present? &&
            (event_types - supported_event_types).empty? &&
            (!params.key?(:filter) || params[:filter] == item.foundational_flow.default_trigger_filter)
        end
      end
    end
  end
end
