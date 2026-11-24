# frozen_string_literal: true

module EE
  module API
    module Ci
      module Helpers
        module RunnerHelpers
          extend ActiveSupport::Concern

          prepended do
            params :create_runner_params_ee do
              optional :token_expires_at, type: DateTime,
                desc: 'Expiration time for the runner authentication token in ISO 8601 format. Must be between 5 ' \
                  'minutes and 21 days in the future and cannot exceed instance, group, or project-level limits. ' \
                  'Only applies to the initial token. Rotated tokens use the computed expiry from settings. ' \
                  'Premium and Ultimate only.'
              optional :token_rotation_deadline, type: DateTime,
                desc: 'Deadline after which token rotation requests are rejected. Requires `token_expires_at` and ' \
                  'must be less than or equal to it. Setting both to the same value disables token rotation. ' \
                  'Cleared on successful rotation. Premium and Ultimate only.'
            end
          end
        end
      end
    end
  end
end
