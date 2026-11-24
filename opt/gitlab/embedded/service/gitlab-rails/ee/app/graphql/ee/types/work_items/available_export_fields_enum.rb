# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module AvailableExportFieldsEnum
        extend ActiveSupport::Concern

        prepended do
          value 'WEIGHT', value: 'weight', description: 'Weight of the work item.'
        end
      end
    end
  end
end
