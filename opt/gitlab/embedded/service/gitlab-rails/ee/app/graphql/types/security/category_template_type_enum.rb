# frozen_string_literal: true

module Types
  module Security
    class CategoryTemplateTypeEnum < BaseEnum
      graphql_name 'SecurityCategoryTemplateType'
      description 'Template type for predefined security categories'

      value 'BUSINESS_IMPACT', value: 'business_impact', description: 'Business impact category.'
      value 'BUSINESS_UNIT', value: 'business_unit', description: 'Business unit category.'
      value 'APPLICATION', value: 'application', description: 'Application category.'
      value 'EXPOSURE', value: 'exposure', description: 'Exposure category.'
    end
  end
end
