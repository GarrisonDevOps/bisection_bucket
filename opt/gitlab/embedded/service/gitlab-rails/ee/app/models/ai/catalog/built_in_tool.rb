# frozen_string_literal: true

module Ai
  module Catalog
    class BuiltInTool
      include ActiveRecord::FixedItemsModel::Model
      include GlobalID::Identification
      include Ai::Catalog::BuiltInToolDefinitions

      attribute :name, :string
      attribute :title, :string
      attribute :description, :string

      validates :name, :title, :description, presence: true

      class << self
        def count
          all.size
        end
      end
    end
  end
end
