# frozen_string_literal: true

require 'action_view/helpers'

module Gitlab
  module Geo
    class GeoNodeStatusCheck
      include ActionView::Helpers::DateHelper
      include ActionView::Helpers::NumberHelper

      GEO_STATUS_COLUMN_WIDTH = 44

      attr_reader :current_node_status, :geo_node

      def initialize(current_node_status, geo_node)
        @current_node_status = current_node_status
        @geo_node = geo_node
      end

      def print_status
        print_current_node_info

        print_geo_role
        print_node_health_status
        print_gitlab_version

        print_sync_settings
        print_db_replication_lag
        print_last_event_id
        print_last_status_report_time

        print_replicators_status
        print_repositories_checked_status
        print_replicators_verification_status

        puts
      end

      def print_replication_verification_status
        print_replicators_status
        print_replicators_verification_status
      end

      def replication_verification_complete?
        checks_status =
          replication_and_verification_checks_status +
          conditional_replication_and_verification_checks_status

        checks_status.compact.all?(100)
      end

      def print_counts_row(description:, failed:, succeeded:, total:, percentage:)
        print "#{description}: ".rjust(GEO_STATUS_COLUMN_WIDTH)
        print Rainbow("failed #{failed}").red, ' / ' if failed.present? && failed > 0
        print "succeeded #{succeeded || 0} / total #{total || 0} "
        puts  using_percentage(percentage)
      end

      private

      def replication_and_verification_checks_status
        [].tap do |status|
          Gitlab::Geo.replication_enabled_replicator_classes.each do |replicator_class|
            next unless current_node_status.count_for(replicator_class).to_i > 0

            status.push current_node_status.synced_in_percentage_for(replicator_class)

            if replicator_class.verification_enabled?
              status.push current_node_status.verified_in_percentage_for(replicator_class)
            end
          end
        end
      end

      def conditional_replication_and_verification_checks_status
        [].tap do |status|
          if Gitlab::CurrentSettings.repository_checks_enabled && current_node_status.repositories_count.to_i > 0 && \
              !Gitlab::Geo.secondary_or_org_migration_target?
            status.push current_node_status.repositories_checked_in_percentage
          end
        end
      end

      def print_current_node_info
        puts
        puts Rainbow('Geo Site Information'.rjust(GEO_STATUS_COLUMN_WIDTH)).yellow
        puts Rainbow('-' * GEO_STATUS_COLUMN_WIDTH).yellow
        print 'Name: '.rjust(GEO_STATUS_COLUMN_WIDTH)
        puts GeoNode.current_node_name
        print 'URL: '.rjust(GEO_STATUS_COLUMN_WIDTH)
        puts GeoNode.current_node_url
      end

      def print_gitlab_version
        print 'This Node\'s GitLab Version: '.rjust(GEO_STATUS_COLUMN_WIDTH)
        puts Gitlab::VERSION
      end

      def print_geo_role
        print 'Geo Role: '.rjust(GEO_STATUS_COLUMN_WIDTH)
        role =
          if Gitlab::Geo.primary?
            'Primary'
          elsif Gitlab::Geo.org_migration_target?
            'Org Migration Target Cell'
          elsif Gitlab::Geo.secondary?
            'Secondary'
          else
            Rainbow('unknown').yellow
          end

        puts role
      end

      def print_node_health_status
        print 'Health Status: '.rjust(GEO_STATUS_COLUMN_WIDTH)

        if current_node_status.healthy?
          puts current_node_status.health_status
        else
          puts Rainbow(current_node_status.health_status).red
        end

        return if current_node_status.healthy?

        print 'Health Status Summary: '.rjust(GEO_STATUS_COLUMN_WIDTH)
        puts Rainbow(current_node_status.health).red
      end

      def print_sync_settings
        puts
        puts Rainbow('Replication Information'.rjust(GEO_STATUS_COLUMN_WIDTH)).yellow
        puts Rainbow('-' * GEO_STATUS_COLUMN_WIDTH).yellow
        print 'Sync Settings: '.rjust(GEO_STATUS_COLUMN_WIDTH)
        puts  geo_node.namespaces.any? ? 'Selective' : 'Full'
      end

      def print_db_replication_lag
        print 'Database replication lag: '.rjust(GEO_STATUS_COLUMN_WIDTH)
        lag = Gitlab::Geo::HealthCheck.new.db_replication_lag_seconds
        if lag.nil?
          puts "N/A"
        else
          puts "#{lag} seconds"
        end
      end

      # rubocop: disable CodeReuse/ActiveRecord
      def print_last_event_id
        print 'Last event ID seen from primary: '.rjust(GEO_STATUS_COLUMN_WIDTH)
        last_event = ::Geo::EventLog.last

        if last_event
          print last_event&.id
          puts " (#{time_ago_in_words(last_event&.created_at)} ago)"

          print 'Last event ID processed: '.rjust(GEO_STATUS_COLUMN_WIDTH)
          cursor_last_event_id = ::Geo::EventLogState.last_processed&.event_id

          if cursor_last_event_id
            print cursor_last_event_id
            last_cursor_event_date =
              ::Geo::EventLog.find_by(id: cursor_last_event_id)&.created_at
            print " (#{time_ago_in_words(last_cursor_event_date)} ago)" if last_cursor_event_date
            puts
          else
            puts 'Not applicable.'
          end
        else
          puts 'Not applicable.'
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def print_last_status_report_time
        print 'Last status report was: '.rjust(GEO_STATUS_COLUMN_WIDTH)

        if current_node_status.updated_at
          puts "#{time_ago_in_words(current_node_status.updated_at)} ago"
        else
          # Only primary node can create a status record in the database so if
          # it does not exist we get unsaved record where updated_at is nil
          puts 'Never'
        end
      end

      # Counted once per replicator for the whole command, since both sections need the counts.
      def replicator_counts(replicator_class)
        @replicator_counts ||= {}
        @replicator_counts[replicator_class] ||=
          if Feature.enabled?(:geo_single_pass_registry_counts, type: :ops) # rubocop:disable Gitlab/FeatureFlagWithoutActor -- instance-wide ops flag
            replicator_class.registry_counts
          else
            # Lazy, so each section only runs the queries it prints.
            Hash.new { |counts, name| counts[name] = replicator_class.public_send(name) } # rubocop:disable GitlabSecurity/PublicSend -- fixed count method names
          end
      end

      def print_replicators_status
        puts
        puts Rainbow('Replication Status'.rjust(GEO_STATUS_COLUMN_WIDTH)).yellow
        puts Rainbow('-' * GEO_STATUS_COLUMN_WIDTH).yellow

        Gitlab::Geo.replication_enabled_replicator_classes.each do |replicator_class|
          counts = replicator_counts(replicator_class)
          print_counts_row(
            description: "#{replicator_class.replicable_title_plural} replicated",
            failed: counts[:failed_count],
            succeeded: counts[:synced_count],
            total: counts[:registry_count],
            percentage: current_node_status.synced_in_percentage_for(replicator_class)
          )
        end

        print_uploads_aggregate_row(
          Gitlab::Geo.upload_partition_replicator_classes.select(&:replication_enabled?), 'replicated',
          failed: current_node_status.uploads_failed_count, succeeded: current_node_status.uploads_synced_count,
          percentage: current_node_status.uploads_synced_in_percentage
        )
      end

      def print_repositories_checked_status
        return unless Gitlab::Geo.primary?
        return unless Gitlab::CurrentSettings.repository_checks_enabled

        print_counts_row(
          description: 'Repositories Checked',
          failed: current_node_status.repositories_checked_failed_count,
          succeeded: current_node_status.repositories_checked_count,
          total: current_node_status.repositories_count,
          percentage: current_node_status.repositories_checked_in_percentage
        )
      end

      def print_replicators_verification_status
        puts
        puts Rainbow('Verification Status'.rjust(GEO_STATUS_COLUMN_WIDTH)).yellow
        puts Rainbow('-' * GEO_STATUS_COLUMN_WIDTH).yellow

        verifiable_replicator_classes = Gitlab::Geo.verification_enabled_replicator_classes

        verifiable_replicator_classes.each do |replicator_class|
          counts = replicator_counts(replicator_class)
          print_counts_row(
            description: "#{replicator_class.replicable_title_plural} verified",
            failed: counts[:verification_failed_count],
            succeeded: counts[:verified_count],
            total: counts[:registry_count],
            percentage: current_node_status.verified_in_percentage_for(replicator_class)
          )
        end

        print_uploads_aggregate_row(
          Gitlab::Geo.upload_partition_replicator_classes.select(&:verification_enabled?), 'verified',
          failed: current_node_status.uploads_verification_failed_count,
          succeeded: current_node_status.uploads_verified_count,
          percentage: current_node_status.uploads_verified_in_percentage
        )
      end

      def print_uploads_aggregate_row(partitions, verb, failed:, succeeded:, percentage:)
        return if ::Geo::UploadReplicator.replication_enabled?

        partition = partitions.first
        return unless partition

        print_counts_row(
          description: "#{partition.replicable_group_title} #{verb}",
          failed: failed,
          succeeded: succeeded,
          total: current_node_status.uploads_registry_count,
          percentage: percentage
        )
      end

      def using_percentage(value)
        "(#{number_to_percentage(
          value.floor,
          precision: 0,
          strip_insignificant_zeros: true
        )})"
      end
    end
  end
end
