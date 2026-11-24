# frozen_string_literal: true

module Gitlab
  module PackageMetadata
    module Connector
      # PDS (PMDB Distribution Service) connector for security advisories.
      #
      # The v3 distribution contract lives in Pds; advisories contribute only
      # their token scope, their archive URL key and their log wording. The
      # endpoint comes from SyncConfiguration::Location.for_advisories.
      class AdvisoriesPds < Pds
        # The `package_advisories` unit primitive shipped in
        # gitlab-cloud-connector 1.54.0.
        def self.unit_primitive
          :package_advisories
        end

        def self.archive_url_key
          'signed_url'
        end

        private

        def dataset_label
          'package advisories'
        end
      end
    end
  end
end
