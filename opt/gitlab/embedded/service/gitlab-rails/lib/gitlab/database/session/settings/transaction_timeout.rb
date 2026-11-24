# frozen_string_literal: true

module Gitlab
  module Database
    module Session
      class Settings
        # Changes transaction_timeout (PostgreSQL 17+) for the session around a block and restores the previous
        # value. On older servers the setting does not exist, so the block runs untouched.
        module TransactionTimeout
          # @param timeout any value PostgreSQL accepts for transaction_timeout, such as '2h',
          #   '500ms', milliseconds as an Integer, or 0 to disable the timeout
          def self.with(connection, timeout, &block)
            return yield unless Gitlab::Database::TransactionTimeout.supported?(connection)

            Settings.with('transaction_timeout', timeout, connection, &block)
          end
        end
      end
    end
  end
end
