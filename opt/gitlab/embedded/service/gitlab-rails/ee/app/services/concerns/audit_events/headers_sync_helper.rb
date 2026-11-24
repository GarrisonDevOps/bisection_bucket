# frozen_string_literal: true

module AuditEvents
  module HeadersSyncHelper
    include AuditEvents::DestinationSyncValidator

    STREAMING_TOKEN_HEADER_KEY = 'X-Gitlab-Event-Streaming-Token'

    def sync_legacy_headers(stream_destination_model, legacy_destination)
      return unless stream_destination_model.config['headers'].present?

      if legacy_destination.instance_level?
        header_class = AuditEvents::Streaming::InstanceHeader
        foreign_key = 'instance_external_audit_event_destination_id'
      else
        header_class = AuditEvents::Streaming::Header
        foreign_key = 'external_audit_event_destination_id'
      end

      ApplicationRecord.transaction do
        header_class.where(foreign_key => legacy_destination.id).delete_all # rubocop:disable CodeReuse/ActiveRecord -- Syncing delete

        stream_destination_model.config['headers'].each do |key, header_data|
          next if key == STREAMING_TOKEN_HEADER_KEY

          attrs = {
            foreign_key => legacy_destination.id,
            :key => key,
            :value => header_data['value'],
            :active => header_data['active'] == true
          }

          new_header = header_class.new(attrs)
          new_header.save!
        end
      end
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        audit_event_destination_model: stream_destination_model.class.name
      )
    end

    def sync_header_to_streaming_destination(destination, header, old_key = nil)
      return unless should_sync_http?(destination)

      return if header.key == STREAMING_TOKEN_HEADER_KEY

      stream_destination = destination.stream_destination

      current_config = stream_destination.config.deep_dup

      if old_key && old_key != header.key && current_config['headers']&.key?(old_key)
        current_config['headers'].delete(old_key)
      end

      current_config['headers'] ||= {}
      current_config['headers'][header.key] = {
        'value' => header.value,
        'active' => header.active
      }

      stream_destination.update(config: current_config)
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        audit_event_destination_model: destination.class.name,
        header_id: header.id
      )
      nil
    end

    def sync_header_deletion_to_streaming_destination(destination, header_key)
      return unless should_sync_http?(destination)

      stream_destination = destination.stream_destination

      current_config = stream_destination.config.deep_dup

      if current_config['headers']&.key?(header_key)
        current_config['headers'].delete(header_key)
        stream_destination.update(config: current_config)
      end
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        audit_event_destination_model: destination.class.name,
        header_key: header_key
      )
      nil
    end

    def sync_http_destination(stream_destination_model, destination)
      remove_streaming_token_from_headers(stream_destination_model)
      sync_legacy_headers(stream_destination_model, destination)
      remove_legacy_streaming_token_headers(destination)
    end

    def remove_streaming_token_from_headers(stream_destination_model)
      config = stream_destination_model.config.deep_dup
      headers = config['headers']

      return unless headers&.delete(STREAMING_TOKEN_HEADER_KEY)

      config.delete('headers') if headers.empty?

      stream_destination_model.update!(config: config)
    end

    def remove_legacy_streaming_token_headers(destination)
      return unless destination.respond_to?(:headers)

      destination.headers
        .where(key: STREAMING_TOKEN_HEADER_KEY) # rubocop:disable CodeReuse/ActiveRecord -- Find and delete protected header set
        .delete_all
    end
  end
end
