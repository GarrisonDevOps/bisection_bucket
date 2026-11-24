# frozen_string_literal: true

module Ai
  module Catalog
    module Agents
      class DestroyService < Ai::Catalog::Items::BaseDestroyService
        private

        def valid?
          super && item.agent?
        end

        def error_no_item
          error('Agent not found')
        end
      end
    end
  end
end
