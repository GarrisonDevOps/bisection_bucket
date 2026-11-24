# frozen_string_literal: true

module Gitlab
  module Database
    module AsyncIndexes
      class IndexCreator < AsyncIndexes::IndexBase
        STATEMENT_TIMEOUT = 20.hours

        private

        override :preconditions_met?
        def preconditions_met?
          !index_exists?
        end

        override :action_type
        def action_type
          'creation'
        end

        override :around_execution
        def around_execution(&block)
          set_statement_timeout(&block)
        end

        def set_statement_timeout
          Gitlab::Database::Session::Settings::StatementTimeout.with(connection, format("%ds", STATEMENT_TIMEOUT)) do
            Gitlab::Database::TransactionTimeout.set(connection, STATEMENT_TIMEOUT)
            yield
          end
        ensure
          Gitlab::Database::TransactionTimeout.reset(connection)
        end
      end
    end
  end
end
