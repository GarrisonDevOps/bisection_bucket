# frozen_string_literal: true

module Banzai
  module Filter
    module Concerns
      module ReferenceResolving
        def reference_resolver
          result[:reference_resolver] ||= context[:reference_resolver] || ReferenceResolver.from_context(context)
        end
      end
    end
  end
end
