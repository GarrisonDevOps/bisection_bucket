# frozen_string_literal: true

module Security
  module SecretDetection
    module Vulnerabilities
      class PartnerTokenService < PartnerTokenServiceBase
        class << self
          def finding_type
            :vulnerability
          end

          def token_status_model
            ::Vulnerabilities::FindingTokenStatus
          end

          def unique_by_column
            :vulnerability_occurrence_id
          end
        end
      end
    end
  end
end
