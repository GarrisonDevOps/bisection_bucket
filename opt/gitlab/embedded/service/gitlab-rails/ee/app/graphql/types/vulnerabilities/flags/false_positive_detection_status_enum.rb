# frozen_string_literal: true

module Types
  module Vulnerabilities
    module Flags
      class FalsePositiveDetectionStatusEnum < BaseEnum
        graphql_name 'VulnerabilityFalsePositiveDetectionStatus'
        description 'Status of vulnerability flag false positive detection'

        ::Vulnerabilities::Flag::FALSE_POSITIVE_DETECTION_STATUSES.each_key do |status|
          value status.to_s.upcase, value: status.to_s, description: "Detection is #{status.to_s.humanize.downcase}"
        end
      end
    end
  end
end
