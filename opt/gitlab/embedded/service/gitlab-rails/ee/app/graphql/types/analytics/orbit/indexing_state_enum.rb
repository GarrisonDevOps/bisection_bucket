# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class IndexingStateEnum < BaseEnum
        graphql_name 'OrbitIndexingState'
        description 'Indexing state of Orbit data.'

        value 'NOT_STARTED', description: 'Indexing has not started.', value: 'not_started'
        value 'INDEXING', description: 'Indexing is in progress.', value: 'syncing'
        value 'READY', description: 'Indexing is complete.', value: 'ready'
        value 'FAILED', description: 'Indexing failed.', value: 'error'
        value 'UNKNOWN', description: 'Indexing state is unknown.', value: 'unknown'
      end
    end
  end
end
