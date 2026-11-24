# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class MaximumAccessTokenLifetimeEnabledMetric < GenericMetric
          value do
            Gitlab::CurrentSettings.max_personal_access_token_lifetime
          end
        end
      end
    end
  end
end
