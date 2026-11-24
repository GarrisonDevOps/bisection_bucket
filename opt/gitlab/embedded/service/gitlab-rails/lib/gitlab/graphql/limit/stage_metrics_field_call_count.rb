# frozen_string_literal: true

module Gitlab
  module Graphql
    module Limit
      class StageMetricsFieldCallCount < FieldCallCount
        def resolve(object:, arguments:, context:)
          root = object.object.namespace.root_ancestor
          if Feature.disabled?(:vsa_stage_metrics_validate_timeframe, root, type: :gitlab_com_derisk)
            return yield(object, arguments)
          end

          super
        end
      end
    end
  end
end
