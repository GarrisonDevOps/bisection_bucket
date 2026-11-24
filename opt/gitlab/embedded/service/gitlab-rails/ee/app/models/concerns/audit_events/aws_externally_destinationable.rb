# frozen_string_literal: true

module AuditEvents
  module AwsExternallyDestinationable
    extend ActiveSupport::Concern

    # Mirrors Seahorse::Util.host_label?, the check the AWS SDK applies to :region,
    # so we never reject a region the SDK would have accepted. Lowercase only:
    # every real region code is lowercase, and an uppercase region reaches SigV4
    # signing and fails at AWS rather than working.
    AWS_REGION_REGEXP = /\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/

    included do
      before_validation :normalize_aws_region, if: :will_save_change_to_aws_region?

      validates :aws_region, presence: true, length: { maximum: 50 }

      validate :aws_region_format, if: :will_save_change_to_aws_region?

      private

      def normalize_aws_region
        self.aws_region = aws_region.strip if aws_region.is_a?(String)
      end

      # Added to :base with the same message AwsDestinationValidator uses, so both
      # storage paths share one translatable string.
      def aws_region_format
        return if aws_region.blank?
        return if aws_region.match?(AWS_REGION_REGEXP)

        errors.add(:base, _('AWS region must be a valid region code, for example us-east-1'))
      end
    end
  end
end
