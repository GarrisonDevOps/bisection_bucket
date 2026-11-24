# frozen_string_literal: true

module Ai
  module Catalog
    class BaseDefinition
      include Gitlab::Utils::StrongMemoize

      def initialize(item, version)
        @item = item
        @version = version
      end

      private

      attr_reader :item, :version
    end
  end
end
