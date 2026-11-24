# frozen_string_literal: true

module Gitlab
  module Database
    module Migrations
      module PreparedAsyncDmlOperationsTesting
        # This is a wrapper for Gitlab::Database::AsyncIndexes::IndexCreator, used to control the STATEMENT_TIMEOUT
        # and creating async indexes synchronously
        class IndexCreator < Gitlab::Database::AsyncIndexes::IndexCreator
          TIMEOUT = 30.seconds

          TIMEOUT_EXCEPTIONS = [ActiveRecord::StatementTimeout, ActiveRecord::AdapterTimeout,
            ActiveRecord::LockWaitTimeout, ActiveRecord::QueryCanceled].freeze

          def perform
            connection.transaction do
              execute_action
            end
          rescue *TIMEOUT_EXCEPTIONS => error
            Gitlab::AppLogger.info(message: error, index: async_index.name)
          ensure
            connection.execute(
              async_index.class.sanitize_sql(
                ['DELETE FROM "postgres_async_indexes" WHERE id = ? /* SYNC_TESTING_EXECUTION */', async_index.id]
              )
            )
          end

          private

          # SET LOCAL ends with the surrounding transaction, so the session keeps the value
          # database.yml configured instead of falling back to the cluster default.
          def execute_action
            Gitlab::Database::Transaction::Settings.set('statement_timeout', format("%ds", TIMEOUT), connection)
            connection.execute(async_index.definition.gsub('CONCURRENTLY ', ''))
          end
        end
      end
    end
  end
end
