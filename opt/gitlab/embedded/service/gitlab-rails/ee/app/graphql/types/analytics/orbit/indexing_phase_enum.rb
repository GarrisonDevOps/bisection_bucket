# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class IndexingPhaseEnum < BaseEnum
        graphql_name 'OrbitIndexingPhase'
        description 'Indexing phase of Orbit data.'

        value 'NOT_STARTED', description: 'Indexing has not started.', value: 'not_started'
        value 'SYNCING', description: 'Indexing is in progress.', value: 'syncing'
        value 'READY', description: 'Indexing is complete.', value: 'ready'
        value 'ERROR', description: 'Indexing failed.', value: 'error'
        value 'UNKNOWN', description: 'Indexing phase is unknown.', value: 'unknown'
      end
    end
  end
end
