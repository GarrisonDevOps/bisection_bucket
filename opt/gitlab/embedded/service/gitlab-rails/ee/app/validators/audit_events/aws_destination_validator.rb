# frozen_string_literal: true

module AuditEvents
  class AwsDestinationValidator < BaseDestinationValidator
    def validate(record)
      if record.is_a?(AuditEvents::ExternallyStreamable) && record.aws?
        validate_attribute_uniqueness(record, ["bucketName"], "aws")
        validate_aws_region(record)
      else
        record.errors.add(:base, _('AwsDestinationValidator validates only aws external audit event destinations.'))
      end
    end

    private

    def validate_aws_region(record)
      return unless record.aws_region_changing?

      region = record.config['awsRegion']
      return if region.blank?
      return if region.is_a?(String) && region.match?(AwsExternallyDestinationable::AWS_REGION_REGEXP)

      record.errors.add(:base, _('AWS region must be a valid region code, for example us-east-1'))
    end
  end
end
