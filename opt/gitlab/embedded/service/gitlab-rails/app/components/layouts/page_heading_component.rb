# frozen_string_literal: true

module Layouts
  class PageHeadingComponent < ViewComponent::Base
    # @param [String] heading
    # @param [Hash] options
    def initialize(heading, description: nil, options: {})
      @heading = heading
      @description = description
      @options = options
    end

    renders_one :heading
    # Replaces the whole heading element, including the `h1`.
    renders_one :heading_wrapper
    renders_one :actions
    renders_one :description
  end
end
