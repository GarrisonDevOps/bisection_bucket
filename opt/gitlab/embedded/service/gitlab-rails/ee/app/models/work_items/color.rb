# frozen_string_literal: true

module WorkItems
  class Color < ApplicationRecord
    self.table_name = 'work_item_colors'

    DEFAULT_COLOR = ::Gitlab::Color.of('#1068bf')

    # Maps the 14 predefined work item color HEX values to their display names.
    # Must stay in sync with EPIC_COLORS in app/assets/javascripts/work_items/constants.js
    COLOR_HEX_TO_NAME = {
      '#1068bf' => 'Blue',
      '#217645' => 'Forest green',
      '#c91c00' => 'Dark red',
      '#9e5400' => 'Coffee',
      '#694cc0' => 'Purple',
      '#de198f' => 'Magenta',
      '#2e90a5' => 'Teal',
      '#55aafe' => 'Light blue',
      '#4dd787' => 'Mint green',
      '#f17763' => 'Rose',
      '#f3ad5d' => 'Apricot',
      '#b7a0fd' => 'Lavender',
      '#fd8cd0' => 'Pink',
      '#6cd3ea' => 'Aqua'
    }.freeze

    attribute :color, ::Gitlab::Database::Type::Color.new, default: DEFAULT_COLOR

    validates :color, color: true, presence: true

    # namespace is required as the sharding key
    belongs_to :namespace, inverse_of: :work_items_colors
    belongs_to :work_item, foreign_key: 'issue_id', inverse_of: :color

    before_validation :set_namespace

    def text_color
      color.contrast
    end

    private

    def set_namespace
      return if work_item.blank?
      return if work_item.namespace == namespace

      self.namespace = work_item.namespace
    end
  end
end
