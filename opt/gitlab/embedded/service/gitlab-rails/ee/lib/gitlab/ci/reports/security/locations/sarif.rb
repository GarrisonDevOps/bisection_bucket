# frozen_string_literal: true

module Gitlab
  module Ci
    module Reports
      module Security
        module Locations
          class Sarif < Base
            include Security::Concerns::FingerprintPathFromFile

            attr_reader :file_path, :start_line, :end_line, :start_column, :end_column

            def initialize(file_path:, start_line: nil, end_line: nil, start_column: nil, end_column: nil)
              @file_path    = file_path
              @start_line   = start_line&.to_i
              @end_line     = end_line&.to_i
              @start_column = start_column&.to_i
              @end_column   = end_column&.to_i
            end

            def fingerprint_data
              "#{file_path}:#{start_line}:#{end_line}"
            end
          end
        end
      end
    end
  end
end
