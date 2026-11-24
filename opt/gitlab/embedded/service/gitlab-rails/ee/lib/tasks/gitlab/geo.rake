# frozen_string_literal: true

GEO_LICENSE_ERROR_TEXT = 'GitLab Geo is not supported with this license. Please contact the sales team: https://about.gitlab.com/sales.'

namespace :gitlab do
  namespace :geo do
    desc "GitLab | Geo | Check replication/verification status"
    task check_replication_verification_status: :environment do
      abort GEO_LICENSE_ERROR_TEXT unless Gitlab::Geo.license_allows?

      current_node_status = GeoNodeStatus.current_node_status
      abort 'Gitlab Geo is not configured for this site' unless current_node_status

      geo_node = current_node_status.geo_node

      unless geo_node.secondary_or_org_migration_target?
        puts Rainbow('This command is only available on a secondary node').red
        exit
      end

      puts

      status_check = Gitlab::Geo::GeoNodeStatusCheck.new(current_node_status, geo_node)

      status_check.print_replication_verification_status
      complete = status_check.replication_verification_complete?

      if complete
        puts Rainbow('SUCCESS - Replication is up-to-date.').green
        exit 0
      else
        puts Rainbow("ERROR - Replication is not up-to-date. \n" \
          "Please see documentation to complete replication: " \
          "https://docs.gitlab.com/ee/administration/geo/disaster_recovery" \
          "/planned_failover.html#ensure-geo-replication-is-up-to-date")
               .red
        exit 1
      end
    end

    desc 'GitLab | Geo | Prevent updates to primary site'
    task prevent_updates_to_primary_site: :environment do
      abort 'This command is only available on a primary node' unless ::Gitlab::Geo.primary?

      Gitlab::Geo::GeoTasks.enable_maintenance_mode
      Gitlab::Geo::GeoTasks.drain_non_geo_queues
    end

    desc 'GitLab | Geo | Wait until replicated and verified'
    task wait_until_replicated_and_verified: :environment do
      abort 'This command is only available on a secondary node' unless ::Gitlab::Geo.secondary_or_org_migration_target?

      Gitlab::Geo::GeoTasks.wait_until_replicated_and_verified
    end

    desc 'GitLab | Geo | Make this node the Geo primary'
    task set_primary_node: :environment do
      abort GEO_LICENSE_ERROR_TEXT unless Gitlab::Geo.license_allows?
      abort 'GitLab Geo primary node already present' if Gitlab::Geo.primary_node.present?

      Gitlab::Geo::GeoTasks.set_primary_geo_node
    end

    desc 'GitLab | Geo | Make this secondary node the primary'
    task set_secondary_as_primary: :environment do
      abort GEO_LICENSE_ERROR_TEXT unless Gitlab::Geo.license_allows?

      Gitlab::SilentMode.enable! if Gitlab::Utils.to_boolean(ENV['ENABLE_SILENT_MODE'], default: false)

      Gitlab::Geo::GeoTasks.set_secondary_as_primary
    end

    desc 'GitLab | Geo | Update Geo primary node URL'
    task update_primary_node_url: :environment do
      abort GEO_LICENSE_ERROR_TEXT unless Gitlab::Geo.license_allows?

      Gitlab::Geo::GeoTasks.update_primary_geo_node_url
    end

    desc 'GitLab | Geo | Print Geo node status'
    task status: :environment do
      abort GEO_LICENSE_ERROR_TEXT unless Gitlab::Geo.license_allows?

      Gitlab::Geo::GeoTasks.abort_if_tracking_database_not_migrated!

      current_node_status = GeoNodeStatus.current_node_status
      abort 'Gitlab Geo is not configured for this site' unless current_node_status

      geo_node = current_node_status.geo_node

      unless geo_node.secondary_or_org_migration_target?
        puts Rainbow('This command is only available on a secondary node').red
        exit
      end

      Gitlab::Geo::GeoNodeStatusCheck.new(current_node_status, geo_node).print_status
    end

    desc 'GitLab | Geo | Reverify container repositories verified in the last N days (DRY_RUN=true to only count)'
    task :reverify_container_repositories_since, [:days] => :environment do |_task, args|
      abort GEO_LICENSE_ERROR_TEXT unless Gitlab::Geo.license_allows?
      abort 'This command is only available on a primary node' unless Gitlab::Geo.primary?

      days = Integer(args[:days] || 7, exception: false)
      abort 'Days must be a positive integer' unless days&.positive?

      verified_after = days.days.ago
      service = Geo::ReverifyContainerRepositoriesService.new(verified_after: verified_after)

      result = if Gitlab::Utils.to_boolean(ENV['DRY_RUN'], default: false)
                 service.dry_run
               else
                 service.execute
               end

      abort result.message unless result.success?

      puts "#{result.message} (verified since #{verified_after.iso8601})"
    end

    namespace :site do
      desc 'GitLab | Geo | Print Geo site role'
      task role: :environment do
        current_node = GeoNode.current_node

        if current_node&.primary?
          puts 'primary'
        elsif current_node&.org_migration_target?
          puts 'org migration target cell'
        elsif current_node&.secondary?
          puts 'secondary'
        else
          puts 'misconfigured'
          exit 1
        end
      end
    end
  end
end
