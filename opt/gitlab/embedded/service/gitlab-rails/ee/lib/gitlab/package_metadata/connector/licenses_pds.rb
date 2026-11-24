# frozen_string_literal: true

module Gitlab
  module PackageMetadata
    module Connector
      # PDS (PMDB Distribution Service) connector for package licenses.
      #
      # The v3 distribution contract lives in Pds; licenses contribute only their
      # token scope, their archive URL key and their log wording. The endpoint
      # comes from SyncConfiguration::Location.for_licenses.
      class LicensesPds < Pds
        # The `package_licenses` unit primitive shipped in
        # gitlab-cloud-connector 1.53.0.
        def self.unit_primitive
          :package_licenses
        end

        def self.archive_url_key
          'url'
        end

        private

        def dataset_label
          'package licenses'
        end
      end
    end
  end
end
