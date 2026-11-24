# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      class UpdateService
        include EventsTracking
        include Gitlab::Utils::StrongMemoize

        def initialize(item_consumer, current_user, params)
          @current_user = current_user
          @item_consumer = item_consumer
          @params = params.slice(:pinned_version_prefix)
        end

        def execute
          return error_no_permissions unless allowed?
          return validation_error if validation_error&.error?

          reset_to_latest_version_for_owner_project

          if item_consumer.update(params)
            track_item_consumer_event(item_consumer, 'update_ai_catalog_item_consumer', item_consumer.flow_trigger)
            send_audit_events(item_consumer, audit_event_name)
            ServiceResponse.success(payload: { item_consumer: item_consumer })
          else
            error_updating
          end
        end

        private

        attr_reader :current_user, :item_consumer, :params

        def allowed?
          Ability.allowed?(current_user, :admin_ai_catalog_item_consumer, item_consumer)
        end

        def error_no_permissions
          error("You don't have permission to update this configuration")
        end

        def audit_event_name
          "update_enabled_ai_catalog_#{item_consumer.item.item_type}"
        end

        # TODO refactor these validations into the `ItemConsumer` model
        # https://gitlab.com/gitlab-org/gitlab/-/issues/581655
        def validation_error
          return unless params.key?(:pinned_version_prefix)

          if params[:pinned_version_prefix].nil?
            return if nil_version_pin_enforced?

            return error_pinned_version_prefix_nil
          end

          error_version_is_not_released if resolved_version.nil? || !resolved_version.released?
        end
        strong_memoize_attr :validation_error

        def error_pinned_version_prefix_nil
          error('pinned_version_prefix must be present')
        end

        def error_version_is_not_released
          error('pinned_version_prefix must resolve to a released version of the agent or flow')
        end

        def error(message)
          ServiceResponse.error(payload: { item_consumer: item_consumer }, message: Array(message))
        end

        def error_updating
          error(item_consumer.errors.full_messages.presence || 'Failed to update this configuration')
        end

        def resolved_version
          @resolved_version ||= item_consumer.item.resolve_version(params[:pinned_version_prefix], track_missing: false)
        end

        def nil_version_pin_enforced?
          item_consumer.project_id.present? && item_consumer.project_id == item_consumer.item.project_id
        end
        strong_memoize_attr :nil_version_pin_enforced?

        def reset_to_latest_version_for_owner_project
          return unless nil_version_pin_enforced?

          # nil defaults to the latest version
          params[:pinned_version_prefix] = nil
        end
      end
    end
  end
end
