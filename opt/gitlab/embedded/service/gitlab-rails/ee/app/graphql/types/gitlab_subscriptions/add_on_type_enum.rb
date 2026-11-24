# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class AddOnTypeEnum < BaseEnum
      graphql_name 'GitlabSubscriptionsAddOnType'
      description 'Types of add-ons'

      value 'DUO_CORE', value: :duo_core, description: 'GitLab Duo Core add-on.', experiment: { milestone: '18.0' }
      value 'CODE_SUGGESTIONS', value: :code_suggestions, description: 'GitLab Duo Pro add-on.'
      value 'DUO_ENTERPRISE', value: :duo_enterprise, description: 'GitLab Duo Enterprise add-on.'
      value 'DUO_AMAZON_Q', value: :duo_amazon_q, description: 'GitLab Duo with Amazon Q add-on.'
    end
  end
end
