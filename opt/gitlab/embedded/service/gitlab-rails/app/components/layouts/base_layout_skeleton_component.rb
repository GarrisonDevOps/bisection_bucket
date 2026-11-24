# frozen_string_literal: true

module Layouts
  # Default skeleton rendered by BaseLayout (and IndexLayout) while `loading` is true.
  # Mirrors app/assets/javascripts/vue_shared/components/base_layout_skeleton.vue.
  class BaseLayoutSkeletonComponent < ViewComponent::Base
    # @param [Integer] rows
    def initialize(rows: 5)
      @rows = rows
    end
  end
end
