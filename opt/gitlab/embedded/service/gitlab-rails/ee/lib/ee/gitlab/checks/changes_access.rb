# frozen_string_literal: true

module EE
  module Gitlab
    module Checks
      module ChangesAccess
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :bulk_access_checks!
        def bulk_access_checks!
          super

          changes_access_logger.instrument(:push_rule_check) { PushRuleCheck.new(self).validate! }
          changes_access_logger.instrument(:secrets_check) do
            ::Gitlab::Checks::SecretPushProtection::SecretsCheck.new(self).validate!
          end
        end
      end
    end
  end
end
