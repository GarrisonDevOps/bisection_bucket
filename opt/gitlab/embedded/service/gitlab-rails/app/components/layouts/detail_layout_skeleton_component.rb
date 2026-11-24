# frozen_string_literal: true

module Layouts
  # Skeleton rendered by DetailLayout while `loading` is true. Reuses the DetailLayout grid
  # classes and only renders regions for the slots the page uses.
  # Mirrors app/assets/javascripts/vue_shared/components/detail_layout_skeleton.vue.
  class DetailLayoutSkeletonComponent < ViewComponent::Base
    DESCRIPTION_LINES = 4
    SIDEBAR_ATTRIBUTES = 6
    WIDGETS = 2
    ACTIVITY_NOTES = 5

    # @param [Boolean] sidebar
    # @param [Boolean] widgets
    # @param [Boolean] activity
    def initialize(sidebar: false, widgets: false, activity: false)
      @sidebar = sidebar
      @widgets = widgets
      @activity = activity
    end
  end
end
