# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class MaximumSshKeysLifetimeEnabledMetric < GenericMetric
          value do
            Gitlab::CurrentSettings.max_ssh_key_lifetime
          end
        end
      end
    end
  end
end
