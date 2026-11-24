# frozen_string_literal: true

module Import
  # Whole-card link for one import source: icon, title, description and a decorative arrow.
  class ActionCardComponent < ViewComponent::Base
    CARD_CLASSES = %w[
      gl-flex gl-items-center gl-gap-5 gl-rounded-lg gl-border gl-border-default gl-bg-subtle gl-p-5
      gl-text-default hover:gl-bg-strong hover:gl-text-default hover:gl-no-underline focus:gl-focus
    ].freeze

    delegate :sprite_icon, to: :helpers

    # @param [String] title
    # @param [String] description
    # @param [String] icon
    # @param [String] href
    # @param [Hash] link_options extra HTML attributes for the link; `class` is merged with the card classes
    def initialize(title:, description:, icon:, href:, link_options: {})
      @title = title
      @description = description
      @icon = icon
      @href = href
      @link_options = link_options
    end

    private

    def link_attributes
      { **@link_options, href: @href, class: [*CARD_CLASSES, @link_options[:class]] }
    end
  end
end
