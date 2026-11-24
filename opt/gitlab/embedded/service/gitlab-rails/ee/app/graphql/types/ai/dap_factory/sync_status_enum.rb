# frozen_string_literal: true

module Types
  module Ai
    module DapFactory
      class SyncStatusEnum < BaseEnum
        graphql_name 'DapFactorySyncStatus'
        description 'Outcome of a Sync of a DAP Software Factory configuration.'

        value 'SYNCED', value: ::Ai::DapFactory::SyncResult::SYNCED,
          description: 'Every stage was applied.'
        value 'PARTIAL', value: ::Ai::DapFactory::SyncResult::PARTIAL,
          description: 'Some stages could not be applied.'
        value 'INVALID', value: ::Ai::DapFactory::SyncResult::INVALID,
          description: 'Nothing was applied because the file is not valid.'
        value 'FAILED', value: ::Ai::DapFactory::SyncResult::FAILED,
          description: 'Sync stopped before applying the file.'
      end
    end
  end
end
