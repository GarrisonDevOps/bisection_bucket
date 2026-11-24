# frozen_string_literal: true

module AuditEvents
  module Group
    module EventTypeFilters
      module Denylist
        class DestroyService < BaseService
          def execute
            existing = destination.event_type_denylist_filters
                                  .audit_event_type_in(event_type_filters)
                                  .pluck_audit_event_type

            missing = event_type_filters - existing
            return ServiceResponse.error(message: error_message(missing)) if missing.present?

            destination.event_type_denylist_filters.audit_event_type_in(event_type_filters).delete_all

            log_audit_event(
              name: 'event_type_filters_deleted',
              message: 'Deleted audit event type denylist filter(s)'
            )

            ServiceResponse.success
          end

          private

          def error_message(missing_filters)
            format(
              _("Couldn't find denylist event type filters where audit event type(s): %{missing_filters}"),
              missing_filters: missing_filters.join(', ')
            )
          end
        end
      end
    end
  end
end
