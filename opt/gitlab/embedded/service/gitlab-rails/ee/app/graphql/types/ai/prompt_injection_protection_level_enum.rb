# frozen_string_literal: true

module Types
  module Ai
    class PromptInjectionProtectionLevelEnum < BaseEnum
      graphql_name 'PromptInjectionProtectionLevel'
      description 'Values for prompt injection protection for a namespace.'

      value 'NO_CHECKS', value: 'no_checks',
        description: 'Turn off scanning entirely. No prompt data is sent to third-party services.'
      value 'LOG_ONLY', value: 'log_only',
        description: 'Scan and log results, but do not block requests.'
      value 'INTERRUPT', value: 'interrupt',
        description: 'Scan and block detected prompt injection attempts.'
    end
  end
end
