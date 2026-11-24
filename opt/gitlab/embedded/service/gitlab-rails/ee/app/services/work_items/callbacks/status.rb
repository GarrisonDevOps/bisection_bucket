# frozen_string_literal: true

module WorkItems
  module Callbacks
    class Status < Base
      include Gitlab::Utils::StrongMemoize

      ALLOWED_PARAMS = [:status, :name].freeze

      def self.execute_without_params?
        true
      end

      def after_create
        return unless status_row_allowed?

        if status_from_params
          update_current_status(status_from_params)
        else
          # Ensure any supported item has a valid status upon creation
          ::WorkItems::Widgets::Statuses::UpdateService.new(
            work_item, current_user, :default
          ).execute
        end
      end

      def after_update
        return if excluded_in_new_type?
        return unless work_item_status_licensed_feature_available?

        update_current_status(status_from_params)
      end

      def after_update_commit
        return unless work_item_status_licensed_feature_available?

        current_status = work_item.current_status
        return unless current_status

        changed = current_status.previous_changes.slice('custom_status_id', 'system_defined_status_id')
        return if changed.empty?

        publish_status_changed_event
      end

      private

      def publish_status_changed_event
        project = work_item.project
        return unless project

        new_status = work_item.current_status.status
        cloud_event = ::WorkItems::StatusChangedEvent.build(
          work_item: work_item, current_user: current_user, status: new_status
        )
        ::Gitlab::EventStore.publish(cloud_event) if cloud_event
      end

      def status_from_params
        status = resolved_status
        return if status.nil?
        return unless lifecycle&.has_status_id?(status.id)
        return unless has_permission?(:"set_#{issuable.to_ability_name}_metadata")

        status
      end
      strong_memoize_attr :status_from_params

      def resolved_status
        return params[:status] if params[:status].present?
        return if status_name.blank?

        status = ::WorkItems::Statuses::Finder
          .new(root_ancestor, { 'name' => status_name })
          .find_single_status

        return status if status && lifecycle&.has_status_id?(status.id)

        raise_error(invalid_status_name_error)
      end

      def status_name
        params[:name]&.strip
      end
      strong_memoize_attr :status_name

      def invalid_status_name_error
        valid_names = lifecycle&.statuses&.map(&:name)&.join(', ')

        format(
          s_("WorkItemStatus|Status '%{name}' is not valid for this work item type. " \
            "Valid statuses are: %{valid_names}."),
          name: status_name,
          valid_names: valid_names
        )
      end

      def update_current_status(status)
        return unless status

        case status.state
        when :open
          if work_item.closed?
            Issues::ReopenService.new(container: work_item.namespace, current_user: current_user)
              .execute(work_item, status: status)
          else
            ::WorkItems::Widgets::Statuses::UpdateService.new(work_item, current_user, status).execute
          end
        when :closed
          if work_item.open?
            Issues::CloseService.new(container: work_item.namespace, current_user: current_user)
              .execute(work_item, status: status)
          else
            ::WorkItems::Widgets::Statuses::UpdateService.new(work_item, current_user, status).execute
          end
        end
      end

      def status_row_allowed?
        ::WorkItems::Statuses::FeatureFlags.write_status_row?(work_item.work_item_type.base_type, root_ancestor)
      end

      def work_item_status_licensed_feature_available?
        root_ancestor&.licensed_feature_available?(:work_item_status)
      end

      def lifecycle
        work_item.work_item_type.status_lifecycle_for(root_ancestor&.id)
      end
      strong_memoize_attr :lifecycle

      def root_ancestor
        work_item.resource_parent&.root_ancestor
      end
      strong_memoize_attr :root_ancestor
    end
  end
end
