# frozen_string_literal: true

module AuditEvents
  module Streaming
    module EventTypeFilters
      class CreateService < BaseService
        def execute
          begin
            create_event_type_filters!
            log_audit_event(name: 'event_type_filters_created', message: 'Created audit event type filter(s)')

            sync_filters
          rescue ActiveRecord::RecordInvalid => e
            return ServiceResponse.error(message: e.message)
          end

          ServiceResponse.success
        end

        private

        def create_event_type_filters!
          model.transaction do
            created = []

            event_type_filters.each do |filter|
              filter_model = destination.event_type_filters.create!(audit_event_type: filter)
              created << filter_model
            end

            created
          end
        end

        def sync_filters
          case destination
          when AuditEvents::ExternalAuditEventDestination, AuditEvents::InstanceExternalAuditEventDestination
            sync_to_streaming_destination if should_sync_to_streaming?
          when AuditEvents::Group::ExternalStreamingDestination, AuditEvents::Instance::ExternalStreamingDestination
            sync_to_legacy_destination if should_sync_to_legacy?
          end
        end

        def should_sync_to_streaming?
          destination.stream_destination.present?
        end

        def should_sync_to_legacy?
          destination.legacy_destination_ref.present?
        end

        def sync_to_streaming_destination
          event_type_filters.each do |filter|
            sync_stream_event_type_filter(destination, filter)
          end
        end

        def sync_to_legacy_destination
          event_type_filters.each do |filter|
            sync_legacy_event_type_filter(destination, filter)
          end
        end
      end
    end
  end
end
