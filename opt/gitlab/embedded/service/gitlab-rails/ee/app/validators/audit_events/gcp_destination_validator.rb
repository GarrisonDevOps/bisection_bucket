# frozen_string_literal: true

module AuditEvents
  class GcpDestinationValidator < BaseDestinationValidator
    def validate(record)
      if record.is_a?(AuditEvents::ExternallyStreamable) && record.gcp?
        validate_attribute_uniqueness(record, %w[logIdName googleProjectIdName], "gcp")
      else
        record.errors.add(:base, _('GcpDestinationValidator validates only gcp external audit event destinations.'))
      end
    end
  end
end
