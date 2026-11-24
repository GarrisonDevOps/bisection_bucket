# frozen_string_literal: true

module AuditEvents
  module Group
    module EventTypeFilters
      module Denylist
        class CreateService < BaseService
          def execute
            conflict_error = conflict_with_existing_filters
            return ServiceResponse.error(message: conflict_error) if conflict_error

            ::AuditEvents::Group::EventTypeFilter.transaction do
              event_type_filters.each do |filter|
                destination.event_type_denylist_filters.create!(audit_event_type: filter, kind: :deny)
              end
            end

            log_audit_event(
              name: 'event_type_filters_created',
              message: 'Created audit event type denylist filter(s)'
            )

            ServiceResponse.success
          rescue ActiveRecord::RecordInvalid => e
            ServiceResponse.error(message: e.message)
          end

          private

          def conflict_with_existing_filters
            existing_deny = destination.event_type_denylist_filters
                                       .audit_event_type_in(event_type_filters)
                                       .pluck_audit_event_type

            if existing_deny.any?
              return format(
                _("Event type(s) already on the denylist: %{filters}"),
                filters: existing_deny.join(', ')
              )
            end

            existing_allow = destination.event_type_filters
                                        .audit_event_type_in(event_type_filters)
                                        .pluck_audit_event_type

            return unless existing_allow.any?

            format(
              _("Event type(s) already on the allowlist and cannot be added to the denylist: %{filters}"),
              filters: existing_allow.join(', ')
            )
          end
        end
      end
    end
  end
end
