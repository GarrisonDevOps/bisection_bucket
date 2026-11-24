# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Reports
        module Security
          module Report
            extend ::Gitlab::Utils::Override
            include ::Gitlab::Utils::StrongMemoize

            override :tracked_context
            def tracked_context
              ::Security::ProjectTrackedContext.for_pipeline(pipeline).tracked.first
            end
            strong_memoize_attr :tracked_context
          end
        end
      end
    end
  end
end
