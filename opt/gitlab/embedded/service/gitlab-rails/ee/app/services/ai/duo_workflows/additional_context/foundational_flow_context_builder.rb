# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module AdditionalContext
      class FoundationalFlowContextBuilder
        CONTEXT_CATEGORY = "agent_platform_%s_context"

        class << self
          include ::Gitlab::Utils::StrongMemoize

          def context_categories
            ::Ai::Catalog::FoundationalFlow.all.to_h do |flow|
              [flow.reference, context_categories_for(flow)]
            end
          end
          strong_memoize_attr :context_categories

          def reserved_context_categories
            context_categories.values.flatten
          end
          strong_memoize_attr :reserved_context_categories

          def context_categories_for(flow)
            [
              CONTEXT_CATEGORY % flow.flow_config_id,
              flow.context_category_alias
            ].compact.uniq
          end
        end

        def initialize(flow:)
          @flow = flow
        end

        def build(runtime_context:)
          fields = flow.resolve_additional_context_for(runtime_context: runtime_context)

          return [] if fields.blank?

          self.class.context_categories_for(flow).map do |category|
            Envelope.wrap(category: category, fields: fields)
          end
        end

        private

        attr_reader :flow
      end
    end
  end
end
