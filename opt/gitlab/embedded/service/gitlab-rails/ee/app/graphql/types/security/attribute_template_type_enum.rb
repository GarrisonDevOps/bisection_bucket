# frozen_string_literal: true

module Types
  module Security
    class AttributeTemplateTypeEnum < BaseEnum
      graphql_name 'SecurityAttributeTemplateType'
      description 'Template type for predefined security attributes'

      value 'MISSION_CRITICAL', value: 'mission_critical', description: 'Mission critical attribute.'
      value 'BUSINESS_CRITICAL', value: 'business_critical', description: 'Business critical attribute.'
      value 'BUSINESS_OPERATIONAL', value: 'business_operational', description: 'Business operational attribute.'
      value 'BUSINESS_ADMINISTRATIVE', value: 'business_administrative',
        description: 'Business administrative attribute.'
      value 'NON_ESSENTIAL', value: 'non_essential', description: 'Non essential attribute.'
    end
  end
end
