# frozen_string_literal: true

module Types
  module Packages
    module Cleanup
      class PolicyType < ::Types::BaseObject
        graphql_name 'PackagesCleanupPolicy'
        description 'A packages cleanup policy designed to keep only packages and packages assets that matter most'

        authorize :admin_package

        field :delete_generic_packages_not_downloaded_in_days,
          GraphQL::Types::Int,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Number of days after which generic packages that have not been downloaded are deleted. ' \
            '`null` when disabled. The value is ignored unless the ' \
            '`packages_cleanup_delete_generic_not_downloaded` feature flag is enabled.'
        field :keep_n_duplicated_package_files,
          Types::Packages::Cleanup::KeepDuplicatedPackageFilesEnum,
          null: false,
          description: 'Number of duplicated package files to retain.'
        field :next_run_at,
          Types::TimeType,
          null: true,
          description: 'Next time that the packages cleanup policy will be executed.'
      end
    end
  end
end
