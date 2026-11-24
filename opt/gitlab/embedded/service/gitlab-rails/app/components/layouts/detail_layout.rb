# frozen_string_literal: true

module Layouts
  class DetailLayout < Layouts::BaseLayout
    # @param [Boolean] sidebar_first puts the sidebar before the content in the DOM at every width,
    #   so it shows on top when the layout stacks
    def initialize(sidebar_first: false, **base_options)
      super(**base_options)
      @sidebar_first = sidebar_first
    end

    renders_one :sidebar
    renders_one :widgets
    renders_one :activity
  end
end
