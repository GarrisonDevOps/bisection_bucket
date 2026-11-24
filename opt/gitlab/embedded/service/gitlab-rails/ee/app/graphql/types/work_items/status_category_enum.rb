# frozen_string_literal: true

module Types
  module WorkItems
    class StatusCategoryEnum < Types::BaseEnum
      graphql_name 'WorkItemStatusCategoryEnum'
      description 'Category of the work item status'

      include ::WorkItems::Statuses::SharedConstants

      CATEGORIES.each_key do |name|
        value name.to_s.upcase, value: name.to_s, description: "#{name.to_s.humanize} status category"
      end

      # Override to handle both symbols and strings
      def self.coerce_result(value, _ctx)
        value.to_s
      end
    end
  end
end
