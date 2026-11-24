# frozen_string_literal: true

module Types
  module Security
    class SortableAnalyzerTypeEnum < Types::BaseEnum
      graphql_name 'SortableAnalyzerType'
      description 'Analyzer types that project lists can be sorted by.'

      ::Security::InventoryFilter::SORTABLE_ANALYZER_COLUMNS.each do |analyzer_type|
        value analyzer_type.to_s.upcase, value: analyzer_type.to_s,
          description: "Sort by #{analyzer_type.to_s.humanize} analyzer status."
      end
    end
  end
end
