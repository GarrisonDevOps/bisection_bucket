# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class ItemReportReasonEnum < BaseEnum
        graphql_name 'AiCatalogItemReportReason'
        description 'Possible reasons for reporting an AI catalog item.'

        value 'IMMEDIATE_SECURITY_THREAT',
          description: 'Contains dangerous code, exploits, or harmful actions.',
          value: 'immediate_security_threat'
        value 'POTENTIAL_SECURITY_THREAT',
          description: 'Hypothetical or low risk security flaws that could be exploited.',
          value: 'potential_security_threat'
        value 'EXCESSIVE_RESOURCE_USAGE',
          description: 'Wasting compute or causing performance issues.',
          value: 'excessive_resource_usage'
        value 'SPAM_OR_LOW_QUALITY',
          description: 'Frequently failing or nuisance activity.',
          value: 'spam_or_low_quality'
        value 'OTHER',
          description: 'Please describe below.',
          value: 'other'
      end
    end
  end
end
