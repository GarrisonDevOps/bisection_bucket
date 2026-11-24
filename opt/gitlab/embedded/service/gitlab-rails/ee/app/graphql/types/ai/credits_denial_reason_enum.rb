# frozen_string_literal: true

module Types
  module Ai
    class CreditsDenialReasonEnum < BaseEnum
      graphql_name 'AiCreditsDenialReason'
      description 'Reason GitLab credits are unavailable.'

      value 'USAGE_BILLING_FORBIDDEN',
        description: 'Usage billing is not available for the account.',
        value: 'usage_billing_forbidden'

      value 'NAMESPACE_MISSING',
        description: 'No namespace to bill the usage to. On GitLab.com, the user must set a default ' \
          'GitLab Duo namespace.',
        value: 'namespace_missing'
    end
  end
end
