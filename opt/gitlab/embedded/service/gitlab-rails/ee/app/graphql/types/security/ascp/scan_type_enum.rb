# frozen_string_literal: true

module Types
  module Security
    module Ascp
      class ScanTypeEnum < BaseEnum
        graphql_name 'AscpScanType'
        description 'Type of ASCP scan (full or incremental).'

        value 'FULL', value: 'full', description: 'Full scan of the entire codebase.'
        value 'INCREMENTAL', value: 'incremental', description: 'Incremental scan based on changes since last scan.'
      end
    end
  end
end
