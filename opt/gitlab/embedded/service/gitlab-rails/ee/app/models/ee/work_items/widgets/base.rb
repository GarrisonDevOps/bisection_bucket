# frozen_string_literal: true

module EE
  module WorkItems
    module Widgets
      module Base
        extend ActiveSupport::Concern

        class_methods do
          def sync_params
            []
          end
        end
      end
    end
  end
end
