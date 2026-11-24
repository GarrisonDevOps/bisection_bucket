# frozen_string_literal: true

module AuditEvents
  class HttpDestinationValidator < BaseDestinationValidator
    def validate(record)
      if record.is_a?(AuditEvents::ExternallyStreamable) && record.http?
        validate_attribute_uniqueness(record, ["url"], "http")
        validate_secret_token(record)
      else
        record.errors.add(:base, _('HttpDestinationValidator validates only http external audit event destinations.'))
      end
    end

    private

    def validate_secret_token(record)
      token_length = record.secret_token.to_s.length

      return if (16..24).cover?(token_length)

      record.errors.add(:secret_token, _('should have length between 16 to 24 characters.'))
    end
  end
end
