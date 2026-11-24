# frozen_string_literal: true

module AuditEvents
  module Streaming
    module StreamableEventTypeFilter
      extend ActiveSupport::Concern

      included do
        scope :audit_event_type_in, ->(audit_event_types) { where(audit_event_type: audit_event_types) }

        validate :valid_event_type?

        def to_s
          audit_event_type
        end

        def self.pluck_audit_event_type
          pluck(:audit_event_type)
        end
      end

      private

      def valid_event_type?
        # There is already a validation for attribute `audit_event_type` for presence: true, so in case if it is nil
        # we are returning from here and not throwing any error, as that validation will handle it.
        return if audit_event_type.nil? || Gitlab::Audit::Type::Definition.defined?(audit_event_type)

        errors.add(:audit_event_type, "with value #{audit_event_type} is undefined.")
      end
    end
  end
end
