# frozen_string_literal: true

module SystemCheck
  module RakeTask
    # Used by gitlab:geo:check rake task
    module GeoTask
      extend RakeTaskHelpers

      def self.name
        'Geo'
      end

      def self.checks
        # If geo_nodes table doesn't exist, only run the prerequisite check
        return [Geo::SystemCheck::GeoNodesCheck] unless GeoNode.connection.table_exists?(:geo_nodes)
        return secondary_checks if Gitlab::Geo.secondary? || Gitlab::Geo.current_node_misconfigured?
        return org_migration_target_checks if Gitlab::Geo.org_migration_target?

        common_checks
      end

      def self.common_checks
        [
          Geo::SystemCheck::LicenseCheck,
          Geo::SystemCheck::EnabledCheck,
          Geo::SystemCheck::CurrentNodeCheck,
          Geo::SystemCheck::GeoDatabasePromotedCheck,
          Geo::SystemCheck::ClocksSynchronizationCheck,
          SystemCheck::App::GitUserDefaultSSHConfigCheck,
          Geo::SystemCheck::AuthorizedKeysCheck,
          Geo::SystemCheck::AuthorizedKeysFlagCheck,
          SystemCheck::App::HashedStorageEnabledCheck,
          SystemCheck::App::HashedStorageAllProjectsCheck,
          Geo::SystemCheck::ContainerRegistryCheck
        ]
      end

      def self.secondary_checks
        [
          Geo::SystemCheck::GeoDatabaseConfiguredCheck,
          Geo::SystemCheck::DatabaseReplicationEnabledCheck,
          Geo::SystemCheck::DatabaseReplicationWorkingCheck,
          Geo::SystemCheck::DatabaseMigrationCheck,
          Geo::SystemCheck::HttpConnectionCheck,
          Geo::SystemCheck::SshPortCheck
        ] + common_checks
      end

      def self.org_migration_target_checks
        [
          Geo::SystemCheck::HttpConnectionCheck
        ] + common_checks
      end
    end
  end
end
