# frozen_string_literal: true

module EE
  module WorkItems
    module Widgets
      module Development
        extend ActiveSupport::Concern

        prepended do
          delegate :feature_flags, to: :work_item
        end
      end
    end
  end
end
