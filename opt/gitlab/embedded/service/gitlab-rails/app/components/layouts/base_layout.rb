# frozen_string_literal: true

module Layouts
  class BaseLayout < ViewComponent::Base
    # @param [String] heading
    # @param [String] description
    # @param [Boolean] page_heading_sr_only
    # @param [Boolean] loading Renders skeleton placeholders instead of the content.
    #   A custom `loading` slot replaces them.
    # @param [Hash] options
    def initialize(heading: nil, description: nil, page_heading_sr_only: false, loading: false, options: {})
      @heading = heading
      @description = description
      @page_heading_sr_only = page_heading_sr_only
      @loading = loading
      @options = options
    end

    renders_one :heading
    renders_one :description
    renders_one :actions
    renders_one :alerts
    # Custom loading state. Replaces all skeletons while `loading` is true.
    renders_one :loading
    # Extension point for layouts built on BaseLayout (e.g. DetailLayout).
    renders_one :loading_skeleton

    private

    def show_skeleton?
      @loading && !loading?
    end

    def show_heading_skeleton?
      show_skeleton? && !heading? && @heading.blank?
    end

    def show_description_skeleton?
      show_skeleton? && !description? && @description.blank?
    end
  end
end
