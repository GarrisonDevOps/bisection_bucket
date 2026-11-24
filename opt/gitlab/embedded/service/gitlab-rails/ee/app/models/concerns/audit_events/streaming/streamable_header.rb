# frozen_string_literal: true

module AuditEvents
  module Streaming
    module StreamableHeader
      extend ActiveSupport::Concern

      STREAMING_TOKEN_HEADER_KEY = "X-Gitlab-Event-Streaming-Token"

      included do
        validates :value, presence: true, length: { maximum: 2000 }
        validates :active, inclusion: { in: [true, false], message: N_('must be a boolean value') }
        validate :ensure_protected_header_not_modified

        scope :active, -> { where(active: true) }

        def to_hash
          { key => value }
        end

        def destination
          if respond_to?(:external_audit_event_destination)
            external_audit_event_destination
          elsif respond_to?(:instance_external_audit_event_destination)
            instance_external_audit_event_destination
          end
        end

        private

        def ensure_protected_header_not_modified
          return unless key.present?
          return unless key.casecmp?(STREAMING_TOKEN_HEADER_KEY)

          errors.add(:key, "cannot be #{STREAMING_TOKEN_HEADER_KEY}")
        end
      end
    end
  end
end
