# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class DestroyService < Ai::Catalog::Items::BaseDestroyService
        private

        def valid?
          super && item.flow?
        end

        def error_no_item
          error('Flow not found')
        end
      end
    end
  end
end
