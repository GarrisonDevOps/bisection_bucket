# frozen_string_literal: true

module AuditEvents
  module CustomHttpExternallyDestinationable
    extend ActiveSupport::Concern

    STREAMING_TOKEN_HEADER_KEY = "X-Gitlab-Event-Streaming-Token"
    MAXIMUM_HEADER_COUNT = 20

    included do
      validates :destination_url, public_url: true, presence: true
      validates :verification_token, presence: true, on: :update
      validate :no_more_than_20_headers?
      validates :verification_token, length: { in: 16..24 }, allow_nil: true

      has_secure_token :verification_token, length: 24

      def audit_details
        destination_url
      end

      def headers_hash
        { STREAMING_TOKEN_HEADER_KEY => verification_token }.merge(headers.active.map(&:to_hash).inject(:merge).to_h)
      end

      private

      # TODO: Remove audit_event_type.present? guard clause once we implement names for all the audit event types.
      # Epic: https://gitlab.com/groups/gitlab-org/-/epics/8497
      def event_type_allowed_to_stream?(audit_event_type)
        return true unless audit_event_type.present?
        return true unless event_type_filters.exists?

        event_type_filters.audit_event_type_in(audit_event_type).exists?
      end

      def no_more_than_20_headers?
        return unless headers.count > MAXIMUM_HEADER_COUNT

        errors.add(:headers, "are limited to #{MAXIMUM_HEADER_COUNT} per destination")
      end
    end
  end
end
