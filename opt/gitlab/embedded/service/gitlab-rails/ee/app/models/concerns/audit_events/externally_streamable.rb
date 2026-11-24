# frozen_string_literal: true

module AuditEvents
  module ExternallyStreamable
    extend ActiveSupport::Concern

    MAXIMUM_NAMESPACE_FILTER_COUNT = 5
    MAXIMUM_DESTINATIONS_PER_ENTITY = 5
    STREAMING_TOKEN_HEADER_KEY = "X-Gitlab-Event-Streaming-Token"

    included do
      include Gitlab::EncryptedAttribute

      before_validation :ensure_config_is_hash
      before_validation :assign_default_name
      before_validation :assign_secret_token_for_http
      before_validation :assign_default_log_id, if: -> { gcp? && config_dirty_or_new? }
      before_validation :normalize_aws_region, if: -> { aws? && aws_region_changing? }
      before_validation :remove_empty_headers_from_config
      before_validation :ensure_protected_header_not_modified

      enum :category, {
        http: 0,
        gcp: 1,
        aws: 2
      }

      validates :name, length: { maximum: 72 }
      validates :category, presence: true

      validate :config_is_properly_formatted

      validates :config, presence: true,
        json_schema: { filename: 'audit_events_http_external_streaming_destination_config' }, if: :http?
      validates :config, presence: true, if: -> { aws? || gcp? }
      validates :config,
        json_schema: { filename: 'audit_events_aws_external_streaming_destination_config' },
        if: -> { aws? && config_dirty_or_new? }
      validates :config,
        json_schema: { filename: 'audit_events_gcp_external_streaming_destination_config' },
        if: -> { gcp? && config_dirty_or_new? }
      validates :secret_token, presence: true, unless: :http?
      # Database constraint allows encrypted_secret_token up to 8208 bytes (8192 + 16 byte auth tag)
      validates :secret_token, length: { maximum: 4096 }, allow_blank: true

      validates_with AuditEvents::HttpDestinationValidator, if: :http?
      validates_with AuditEvents::AwsDestinationValidator, if: :aws?
      validates_with AuditEvents::GcpDestinationValidator, if: :gcp?

      attr_encrypted :secret_token,
        mode: :per_attribute_iv,
        key: :db_key_base_32,
        algorithm: 'aes-256-gcm',
        encode: false,
        encode_iv: false

      scope :configs_of_parent, ->(record_id, category) {
        id_not_in(record_id).where(category: category).limit(MAXIMUM_DESTINATIONS_PER_ENTITY).pluck(:config)
      }

      scope :allowed_for_event_type, ->(event_type) {
        next all if event_type.blank?

        filter_class = reflect_on_association(:event_type_filters).klass
        destination_filters = filter_class
          .where(filter_class.arel_table[:external_streaming_destination_id].eq(arel_table[:id]))
        allowlist_filters = destination_filters.allowlist

        # Mirrors event_type_allowed_to_stream? so denylisted events are never enqueued.
        where_not_exists(allowlist_filters)
          .or(where_exists(allowlist_filters.audit_event_type_in(event_type)))
          .where_not_exists(destination_filters.denylist.audit_event_type_in(event_type))
      }

      def config
        stored_config = super

        return stored_config unless stored_config.is_a?(String)

        begin
          ::Gitlab::Json.safe_parse(stored_config)
        rescue JSON::ParserError
          stored_config
        end
      end

      def headers_hash
        return {} unless http?

        (config['headers'] || {})
          .select { |_, h| h['active'] == true }
          .transform_values { |h| h['value'] }
          .merge(STREAMING_TOKEN_HEADER_KEY => secret_token)
      end

      def allowed_to_stream?(event_type, audit_event)
        event_type_allowed_to_stream?(event_type) &&
          namespace_allowed_to_stream?(audit_event)
      end

      def aws_region_changing?
        return false unless config.is_a?(Hash)
        return true if new_record?

        previous = config_was.is_a?(Hash) ? config_was['awsRegion'] : nil
        previous != config['awsRegion']
      end

      private

      # Guards everything that reads or rewrites config. A destination already
      # storing a value the schema patterns reject must stay renameable and
      # deactivatable, so none of it runs on a save that leaves config alone.
      def config_dirty_or_new?
        config_changed? || new_record?
      end

      def config_is_properly_formatted
        return unless config_dirty_or_new?

        return if config.is_a?(Hash)

        errors.add(:config, "must be a hash")
      end

      def ensure_config_is_hash
        return unless config.is_a?(String)

        begin
          self.config = ::Gitlab::Json.safe_parse(config)
        rescue JSON::ParserError
          # Let validation handle this
        end
      end

      def assign_default_name
        self.name ||= "Destination_#{SecureRandom.uuid}"
      end

      def assign_default_log_id
        config["logIdName"] = "audit-events" if config["logIdName"].blank?
      end

      def normalize_aws_region
        return unless config.is_a?(Hash)
        return unless config["awsRegion"].is_a?(String)

        config["awsRegion"] = config["awsRegion"].strip
      end

      def assign_secret_token_for_http
        return unless http?

        self.secret_token ||= SecureRandom.base64(18)
      end

      def sync_helper?
        (new_record? && legacy_destination_ref.present?) || (persisted? && changes.key?('secret_token'))
      end

      def ensure_protected_header_not_modified
        return unless config_changed?

        old_config = config_was || {}
        new_config = config || {}

        old_headers = old_config['headers'] || {}
        new_headers = new_config['headers'] || {}

        old_headers_upcase = old_headers.transform_keys(&:upcase)
        new_headers_upcase = new_headers.transform_keys(&:upcase)
        protected_key_upcase = STREAMING_TOKEN_HEADER_KEY.upcase

        return unless !old_headers_upcase.key?(protected_key_upcase) && new_headers_upcase.key?(protected_key_upcase)
        return if sync_helper?

        errors.add(:config, "headers cannot contain #{STREAMING_TOKEN_HEADER_KEY}")
      end

      def remove_empty_headers_from_config
        return unless http?
        return unless config.is_a?(Hash)

        config.delete('headers') if config['headers'] == {}
      end

      def event_type_allowed_to_stream?(audit_event_type)
        return true unless audit_event_type.present?
        return false if event_type_denylisted?(audit_event_type)
        return true unless filters_any?(event_type_filters)

        filters_match_event_type?(event_type_filters, audit_event_type)
      end

      def event_type_denylisted?(audit_event_type)
        filters_match_event_type?(event_type_denylist_filters, audit_event_type)
      end

      # Use the in-memory collection when the association is preloaded (batched
      # NATS consumer, avoids an N+1); fall back to a query otherwise (per-event
      # Sidekiq path). Behaviour is identical either way.
      def filters_any?(filters)
        return filters.any? if filters.loaded?

        filters.exists?
      end

      def filters_match_event_type?(filters, audit_event_type)
        return filters.any? { |filter| filter.audit_event_type == audit_event_type } if filters.loaded?

        filters.audit_event_type_in(audit_event_type).exists?
      end

      def namespace_allowed_to_stream?(audit_event)
        return true unless filters_any?(namespace_filters)

        namespace = audit_event.streamable_namespace if audit_event.respond_to?(:streamable_namespace)
        return true if namespace.nil?

        # For ProjectNamespace audit events - exact match only
        if namespace.is_a?(::Namespaces::ProjectNamespace)
          return namespace_filters.any? { |filter| filter.namespace_id == namespace.id }
        end

        ancestor_ids = namespace.self_and_ancestor_ids

        namespace_filters.any? do |filter|
          if filter.namespace.is_a?(::Namespaces::ProjectNamespace)
            # Project filter matches exact namespace
            namespace.id == filter.namespace_id
          else
            # Group filter matches if it's an ancestor
            ancestor_ids.include?(filter.namespace_id)
          end
        end
      end
    end
  end
end
