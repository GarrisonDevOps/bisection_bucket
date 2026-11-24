# frozen_string_literal: true

module Ai
  module BillableUsage
    # Forwards the billable_usage context of each Snowplow structured event sent by a
    # self-hosted AI gateway to the billing client, which persists it locally on
    # offline-licensed instances.
    class IngestService
      BILLABLE_USAGE_SCHEMA_PREFIX = 'iglu:com.gitlab/billable_usage/'

      def self.enabled?
        ::Gitlab::BillingEvents::Client.new.local_persistence_enabled?
      end

      def initialize(events)
        @events = events
      end

      def execute
        return ServiceResponse.error(message: 'Events collector is not available') unless self.class.enabled?
        return ServiceResponse.error(message: 'Invalid Snowplow payload') unless events.is_a?(Array)

        forwarded_events = events.count { |event| forward(event) }

        ServiceResponse.success(payload: { forwarded_events: forwarded_events })
      end

      private

      attr_reader :events

      # Returns true once the event is handed to the billing client. The client logs
      # and swallows its own failures, so this does not mean the event was persisted.
      def forward(event)
        return false unless event.is_a?(Hash)

        context = billable_usage_context(event)
        return false unless context

        namespace = namespace_for(context)
        return log_skipped(context) unless namespace

        ::Gitlab::BillingEvents::Client.track_billing_event(
          event_type: context['event_type'],
          category: event['se_ca'],
          quantity: context['quantity'],
          unit_of_measure: context['unit_of_measure'],
          namespace: namespace,
          project: project_for(context),
          idempotency_key: context['event_id'],
          timestamp: parse_timestamp(context['timestamp']),
          metadata: context['metadata']
        )

        true
      end

      def billable_usage_context(event)
        context = decode_contexts(event).find do |ctx|
          ctx.is_a?(Hash) && ctx['schema'].to_s.start_with?(BILLABLE_USAGE_SCHEMA_PREFIX)
        end

        data = context&.dig('data')
        data if data.is_a?(Hash)
      end

      # The Snowplow tracker protocol carries contexts either URL-safe base64 encoded in
      # `cx` or as plain JSON in `co`.
      def decode_contexts(event)
        raw = event['cx'].present? ? Base64.urlsafe_decode64(event['cx']) : event['co']
        return [] if raw.blank?

        envelope = ::Gitlab::Json.safe_parse(raw)
        envelope.is_a?(Hash) ? Array(envelope['data']) : []
      rescue ArgumentError, JSON::ParserError
        []
      end

      def namespace_for(context)
        namespace_id = context['namespace_id'] || context['root_namespace_id']
        return unless namespace_id

        ::Namespace.find_by_id(namespace_id)
      end

      def project_for(context)
        return unless context['project_id']

        ::Project.find_by_id(context['project_id'])
      end

      def parse_timestamp(value)
        ::ActiveSupport::TimeZone['UTC'].parse(value.to_s)
      rescue ArgumentError
        nil
      end

      def log_skipped(context)
        ::Gitlab::AppLogger.warn(
          message: 'BillableUsage::IngestService: billing event skipped, namespace not found',
          event_type: context['event_type'],
          event_id: context['event_id'],
          namespace_id: context['namespace_id'],
          root_namespace_id: context['root_namespace_id']
        )

        false
      end
    end
  end
end
