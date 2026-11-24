# frozen_string_literal: true

module EE
  module Banzai
    module Filter
      # HTML filter that appends extra information to issuable links.
      # Runs as a post-process filter as issuable might change while
      # Markdown is in the cache.
      #
      # This filter supports cross-project references.
      module IssuableReferenceExpansionFilter
        extend ::Gitlab::Utils::Override

        private

        override :expand_reference_with_summary
        def expand_reference_with_summary(node, issuable)
          issuable = issuable.work_item if issuable.is_a?(Epic) && issuable.work_item

          super
        end
      end
    end
  end
end
