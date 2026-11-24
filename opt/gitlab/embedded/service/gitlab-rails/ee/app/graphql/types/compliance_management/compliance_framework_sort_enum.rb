# frozen_string_literal: true

module Types
  module ComplianceManagement
    class ComplianceFrameworkSortEnum < BaseEnum
      graphql_name 'ComplianceFrameworkSort'
      description 'Values for sorting compliance frameworks.'

      value 'NAME_ASC', 'Sort by compliance framework name, ascending order.', value: :name_asc
      value 'NAME_DESC', 'Sort by compliance framework name, descending order.', value: :name_desc
      value 'UPDATED_AT_ASC', 'Sort by compliance framework updated date, ascending order.', value: :updated_at_asc
      value 'UPDATED_AT_DESC', 'Sort by compliance framework updated date, descending order.', value: :updated_at_desc
    end
  end
end
