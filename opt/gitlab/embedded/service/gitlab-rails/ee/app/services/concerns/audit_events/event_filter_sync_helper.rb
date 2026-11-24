# frozen_string_literal: true

# rubocop:disable CodeReuse/ActiveRecord -- Helper is used to manage syncing data between legacy and stream models

module AuditEvents
  module EventFilterSyncHelper
    include AuditEvents::DestinationSyncValidator

    def sync_stream_event_type_filter(legacy_destination_model, audit_event_type)
      return unless should_sync_http?(legacy_destination_model)

      stream_destination = legacy_destination_model.stream_destination

      filter_class = "#{audit_event_namespace(stream_destination)}::EventTypeFilter".constantize

      existing = filter_class.find_by(
        external_streaming_destination_id: stream_destination.id,
        audit_event_type: audit_event_type
      )

      unless existing
        attrs = {
          audit_event_type: audit_event_type,
          external_streaming_destination_id: stream_destination.id
        }

        attrs[:namespace_id] = stream_destination.group_id unless stream_destination.instance_level?

        filter_class.create!(attrs)
      end

    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e, audit_event_destination_model: legacy_destination_model.class.name)
      nil
    end

    def sync_legacy_event_type_filter(stream_destination_model, audit_event_type)
      return unless stream_destination_model.legacy_destination_ref.present?

      legacy_destination = stream_destination_model.legacy_destination
      return unless legacy_destination

      filter_class = if legacy_destination.instance_level?
                       AuditEvents::Streaming::InstanceEventTypeFilter
                     else
                       AuditEvents::Streaming::EventTypeFilter
                     end

      foreign_key = if legacy_destination.instance_level?
                      'instance_external_audit_event_destination_id'
                    else
                      'external_audit_event_destination_id'
                    end

      existing_filter = filter_class.where(foreign_key => legacy_destination.id,
        audit_event_type: audit_event_type).first

      unless existing_filter
        attrs = {
          foreign_key => legacy_destination.id,
          :audit_event_type => audit_event_type
        }

        new_filter = filter_class.new(attrs)
        new_filter.save!
      end

      true
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e, audit_event_destination_model: stream_destination_model.class.name)
      nil
    end

    def sync_delete_legacy_event_type_filter(stream_destination_model, audit_event_types = nil)
      return unless stream_destination_model.legacy_destination_ref.present?

      legacy_destination = stream_destination_model.legacy_destination
      return unless legacy_destination

      filter_class = if legacy_destination.instance_level?
                       AuditEvents::Streaming::InstanceEventTypeFilter
                     else
                       AuditEvents::Streaming::EventTypeFilter
                     end

      relation_name = if legacy_destination.instance_level?
                        :instance_external_audit_event_destination_id
                      else
                        :external_audit_event_destination_id
                      end

      ApplicationRecord.transaction do
        if audit_event_types.present?
          filter_class.where(
            relation_name => legacy_destination.id,
            audit_event_type: audit_event_types
          ).delete_all
        else
          filter_class.where(relation_name => legacy_destination.id).delete_all
        end
      end
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        audit_event_destination_model: stream_destination_model.class.name
      )
      nil
    end

    def sync_delete_stream_event_type_filter(legacy_destination_model, audit_event_types = nil)
      return unless should_sync_http?(legacy_destination_model)

      stream_destination = legacy_destination_model.stream_destination

      filter_class = "#{audit_event_namespace(stream_destination)}::EventTypeFilter".constantize
      ApplicationRecord.transaction do
        if audit_event_types.present?
          filter_class.where(
            external_streaming_destination_id: stream_destination.id,
            audit_event_type: audit_event_types
          ).delete_all
        else
          filter_class.where(
            external_streaming_destination_id: stream_destination.id
          ).delete_all
        end
      end
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e, audit_event_destination_model: legacy_destination_model.class.name)
      nil
    end

    private

    def audit_event_namespace(destination)
      destination.instance_level? ? 'AuditEvents::Instance' : 'AuditEvents::Group'
    end
  end
end
# rubocop:enable CodeReuse/ActiveRecord
