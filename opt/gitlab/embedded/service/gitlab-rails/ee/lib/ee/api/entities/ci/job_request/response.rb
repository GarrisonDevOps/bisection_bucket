# frozen_string_literal: true

module EE
  module API
    module Entities
      module Ci
        module JobRequest
          module Response
            extend ActiveSupport::Concern

            prepended do
              expose :secrets_configuration, as: :secrets, if: ->(build, _) { build.ci_secrets_management_available? }
              expose :policy_options, if: ->(build, _) do
                build&.project&.licensed_feature_available?(:security_orchestration_policies)
              end
            end
          end
        end
      end
    end
  end
end
