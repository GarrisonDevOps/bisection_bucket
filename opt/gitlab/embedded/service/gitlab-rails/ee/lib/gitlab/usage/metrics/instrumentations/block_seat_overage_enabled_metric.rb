# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class BlockSeatOverageEnabledMetric < GenericMetric
          value do
            ::Gitlab::CurrentSettings.seat_control_block_overages?
          end
        end
      end
    end
  end
end
