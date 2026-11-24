# frozen_string_literal: true

module Gitlab
  module Database
    module Migrations
      module TimeoutHelpers
        # Long-running migrations may take more than the timeout allowed by
        # the database. Disable the session's statement timeout to ensure
        # migrations don't get killed prematurely. On PostgreSQL 17+ the
        # transaction timeout is disabled for the same scope.
        #
        # There are two possible ways to disable the statement timeout:
        #
        # - Per transaction (this is the preferred and default mode)
        # - Per connection (restored to the previous value when the block ends)
        #
        # When using a per connection disable statement, code must be inside
        # a block so the previous values are restored after the block finishes.
        # Called with a transaction already open, the block form lifts the
        # timeouts for that transaction only, as the blockless form does.
        def disable_statement_timeout
          if block_given?
            if connection.transaction_open?
              disable_timeouts_for_transaction

              yield
            else
              Gitlab::Database::Session::Settings::StatementTimeout.with(connection, 0) do
                Gitlab::Database::Session::Settings::TransactionTimeout.with(connection, 0) { yield }
              end
            end
          else
            unless transaction_open?
              raise <<~ERROR
                Cannot call disable_statement_timeout() without a transaction open or outside of a transaction block.
                If you don't want to use a transaction wrap your code in a block call:

                disable_statement_timeout { # code that requires disabled statement here }

                This will make sure statement_timeout is disabled before and restored after the block execution is finished.
              ERROR
            end

            disable_timeouts_for_transaction
          end
        end

        private

        def disable_timeouts_for_transaction
          execute('SET LOCAL statement_timeout TO 0')
          Gitlab::Database::TransactionTimeout.disable(connection, local: true)
        end
      end
    end
  end
end
