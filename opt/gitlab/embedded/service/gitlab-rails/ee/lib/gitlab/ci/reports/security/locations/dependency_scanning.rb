# frozen_string_literal: true

module Gitlab
  module Ci
    module Reports
      module Security
        module Locations
          class DependencyScanning < Base
            include Security::Concerns::FingerprintPathFromFile

            attr_reader :file_path, :package_name, :package_version, :files

            def initialize(file_path:, package_name:, package_version: nil, files: nil)
              @file_path = file_path
              @package_name = package_name
              @package_version = package_version
              @files = files
            end

            def fingerprint_data
              "#{file_path}:#{package_name}"
            end
          end
        end
      end
    end
  end
end
