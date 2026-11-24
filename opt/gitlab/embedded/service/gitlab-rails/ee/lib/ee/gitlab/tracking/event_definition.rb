# frozen_string_literal: true

module EE
  module Gitlab
    module Tracking
      module EventDefinition
        extend ::Gitlab::Utils::Override
        extend ActiveSupport::Concern

        override :extra_trackers

        def extra_trackers
          super.reverse_merge(default_extra_trackers)
        end

        private

        def default_extra_trackers
          {
            ::Gitlab::Tracking::AiTracking => {}
          }
        end
      end
    end
  end
end
