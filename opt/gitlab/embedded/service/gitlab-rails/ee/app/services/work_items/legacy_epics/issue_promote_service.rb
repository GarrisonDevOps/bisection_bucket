# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    class IssuePromoteService < ::WorkItems::DataSync::BaseService
      PromoteError = Class.new(StandardError)

      def initialize(container:, current_user:, params: {})
        @container = container
        @current_user = current_user
        @params = params
      end

      def execute(issue, epic_group = nil)
        @target_namespace = epic_group || issue.project.group
        @work_item = ::WorkItem.find(issue.id)

        result = super()

        raise PromoteError, Array.wrap(result.message).to_sentence if result.error?

        result.payload[:work_item].sync_object
      end

      class << self
        def transaction_callback(new_work_item, work_item, current_user)
          SystemNoteService.issue_promoted(new_work_item.sync_object, work_item, current_user, direction: :from)
          SystemNoteService.issue_promoted(work_item, new_work_item.sync_object, current_user, direction: :to)

          work_item.update(promoted_to_epic: new_work_item.sync_object)

          ::Issues::CloseService.new(container: work_item.project, current_user: current_user)
            .execute(work_item, notifications: false, system_note: true)
        end
      end

      private

      attr_reader :work_item, :target_namespace

      def verify_work_item_action_permission
        if target_namespace.nil?
          return error(_('Cannot promote issue because it does not belong to a group.'),
            :unprocessable_entity)
        end

        unless can_promote?
          return error(_('Cannot promote issue due to insufficient permissions.'),
            :unprocessable_entity)
        end

        if work_item.promoted_to_epic_id.present?
          return error(_('Issue already promoted to epic.'),
            :unprocessable_entity)
        end

        return error(_('Promotion is not supported.'), :unprocessable_entity) unless work_item.supports_epic?

        if work_item.work_item_parent && !target_namespace.licensed_feature_available?(:subepics)
          return error(_('Promotion is not supported.'), :unprocessable_entity)
        end

        success({})
      end

      def can_promote?
        Ability.allowed?(current_user, :admin_work_item, work_item) &&
          Ability.allowed?(current_user, :create_epic, target_namespace)
      end

      # The target type is hard-coded to :epic in `data_sync_action`, so the
      # BaseService verification step has nothing to resolve.
      def skip_target_work_item_type_resolution?
        true
      end

      def data_sync_action
        WorkItems::DataSync::Handlers::CopyDataHandler.new(
          work_item: work_item,
          target_namespace: target_namespace,
          current_user: current_user,
          target_work_item_type: ::WorkItems::TypesFramework::Provider.new(target_namespace).find_by_base_type(:epic),
          params: { operation: :promote },
          overwritten_params: {
            author: current_user, created_at: nil, updated_by: nil, updated_at: nil,
            last_edited_at: nil, last_edited_by: nil, closed_at: work_item.closed_at, closed_by: work_item.closed_by,
            duplicated_to_id: nil, moved_to_id: nil, promoted_to_epic_id: nil,
            upvotes_count: 0, blocking_issues_count: 0,
            state_id: work_item.state_id
          }
        ).execute
      end
    end
  end
end
