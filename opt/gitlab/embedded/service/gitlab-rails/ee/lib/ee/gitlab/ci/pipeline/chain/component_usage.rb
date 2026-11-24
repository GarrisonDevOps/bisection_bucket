# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module ComponentUsage
            extend ::Gitlab::Utils::Override
            include ::Gitlab::Utils::StrongMemoize

            private

            override :included_components
            def included_components
              policy_components = command
                .pipeline_policy_context
                .pipeline_execution_context
                .policy_pipelines_included_components

              (super + policy_components).uniq
            end
            strong_memoize_attr :included_components
          end
        end
      end
    end
  end
end
