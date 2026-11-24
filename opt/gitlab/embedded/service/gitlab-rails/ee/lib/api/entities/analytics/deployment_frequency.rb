# frozen_string_literal: true

module API
  module Entities
    module Analytics
      class DeploymentFrequency < Grape::Entity
        format_with(:iso8601_date) { |datetime| datetime.to_date.iso8601 }

        expose :value, documentation: { type: 'Integer' }
        expose :from, format_with: :iso8601_date, documentation: { type: 'Date' }
        expose :to, format_with: :iso8601_date, documentation: { type: 'Date' }
      end
    end
  end
end
