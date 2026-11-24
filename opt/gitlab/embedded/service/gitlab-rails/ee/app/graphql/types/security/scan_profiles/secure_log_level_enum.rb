# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class SecureLogLevelEnum < BaseEnum
        graphql_name 'SecurityScanProfileSecureLogLevel'
        description 'Logging level used by the analyzer.'

        value 'FATAL', value: 'fatal', description: 'Fatal messages only.', experiment: { milestone: '19.5' }
        value 'ERROR', value: 'error', description: 'Error messages and above.', experiment: { milestone: '19.5' }
        value 'WARN', value: 'warn', description: 'Warning messages and above.', experiment: { milestone: '19.5' }
        value 'INFO', value: 'info', description: 'Informational messages and above.', experiment: { milestone: '19.5' }
        value 'DEBUG', value: 'debug', description: 'Debug messages and above.', experiment: { milestone: '19.5' }
      end
    end
  end
end
