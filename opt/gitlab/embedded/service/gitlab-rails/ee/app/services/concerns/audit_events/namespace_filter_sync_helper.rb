# frozen_string_literal: true

# rubocop:disable CodeReuse/ActiveRecord -- Helper is used to manage syncing data between legacy and stream models

module AuditEvents
  module NamespaceFilterSyncHelper
    include AuditEvents::DestinationSyncValidator

    LEGACY_INSTANCE_FILTER_FK = 'audit_events_instance_external_audit_event_destination_id'
    LEGACY_GROUP_FILTER_FK = 'external_audit_event_destination_id'

    def sync_stream_namespace_filter(legacy_destination_model, namespace)
      return unless should_sync_http?(legacy_destination_model)

      stream_destination = legacy_destination_model.stream_destination

      filter_class = stream_filter_class(legacy_destination_model.instance_level?)

      filter = filter_class.find_or_initialize_by(
        external_streaming_destination_id: stream_destination.id
      )

      filter.namespace_id = namespace.id
      filter.save!

      filter
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e, audit_event_destination_model: legacy_destination_model.class.name)
      nil
    end

    def sync_legacy_namespace_filter(stream_destination_model, namespace)
      return unless stream_destination_model.legacy_destination_ref.present?
      return unless stream_destination_model.http?

      legacy_destination = stream_destination_model.legacy_destination
      return unless legacy_destination

      filter_class = legacy_filter_class(legacy_destination)

      foreign_key = if legacy_destination.instance_level?
                      LEGACY_INSTANCE_FILTER_FK
                    else
                      LEGACY_GROUP_FILTER_FK
                    end

      existing_filter = filter_class.where(foreign_key => legacy_destination.id).first

      if existing_filter
        existing_filter.namespace = namespace
        existing_filter.save!
        existing_filter
      else
        attrs = {
          foreign_key => legacy_destination.id,
          :namespace_id => namespace.id
        }

        new_filter = filter_class.new(attrs)
        new_filter.save!

        new_filter
      end
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        audit_event_destination_model: stream_destination_model.class.name
      )
      nil
    end

    def sync_delete_stream_namespace_filter(legacy_destination_model)
      return unless should_sync_http?(legacy_destination_model)

      filter_class = stream_filter_class(legacy_destination_model.instance_level?)

      stream_destination = legacy_destination_model.stream_destination
      filter_class.where(
        external_streaming_destination_id: stream_destination.id
      ).delete_all
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e, audit_event_destination_model: legacy_destination_model.class.name)
      nil
    end

    def sync_delete_legacy_namespace_filter(stream_destination_model)
      return unless stream_destination_model.legacy_destination_ref.present?
      return unless stream_destination_model.http?

      legacy_destination = stream_destination_model.legacy_destination
      return unless legacy_destination

      filter_class = legacy_filter_class(legacy_destination)

      foreign_key = if legacy_destination.instance_level?
                      LEGACY_INSTANCE_FILTER_FK
                    else
                      LEGACY_GROUP_FILTER_FK
                    end

      filter_class.where(foreign_key => legacy_destination.id).delete_all

    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        audit_event_destination_model: stream_destination_model.class.name
      )
      nil
    end

    private

    def stream_filter_class(is_instance)
      if is_instance
        ::AuditEvents::Instance::NamespaceFilter
      else
        ::AuditEvents::Group::NamespaceFilter
      end
    end

    def legacy_filter_class(legacy_destination)
      if legacy_destination.instance_level?
        AuditEvents::Streaming::HTTP::Instance::NamespaceFilter
      else
        AuditEvents::Streaming::HTTP::NamespaceFilter
      end
    end
  end
end
# rubocop:enable CodeReuse/ActiveRecord
