# frozen_string_literal: true

module Ai
  module Catalog
    module ThirdPartyFlows
      class DestroyService < Ai::Catalog::Items::BaseDestroyService
        private

        def valid?
          super && item.third_party_flow?
        end

        def error_no_item
          error('Third Party Flow not found')
        end
      end
    end
  end
end
