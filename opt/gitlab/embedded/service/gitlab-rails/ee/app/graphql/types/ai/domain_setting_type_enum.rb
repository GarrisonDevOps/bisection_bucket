# frozen_string_literal: true

module Types
  module Ai
    class DomainSettingTypeEnum < BaseEnum
      graphql_name 'AiDomainSettingType'
      description 'Type of domain setting to retrieve for AI features.'

      value 'ALLOWED', value: 'allowed', description: 'Domains that are allowed.'
      value 'DENIED', value: 'denied', description: 'Domains that are denied.'
    end
  end
end
