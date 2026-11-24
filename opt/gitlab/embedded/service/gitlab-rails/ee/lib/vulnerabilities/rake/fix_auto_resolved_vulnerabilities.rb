# frozen_string_literal: true

module Vulnerabilities
  module Rake
    class FixAutoResolvedVulnerabilities
      include Gitlab::Database::Migrations::BatchedBackgroundMigrationHelpers

      MIGRATION = 'FixVulnerabilitiesTransitionedFromDismissedToResolved'
      INSTANCE_ARG = 'instance'

      def initialize(args, revert: false)
        @namespace_id = args[:namespace_id]
        @revert = revert
      end

      attr_reader :namespace_id, :revert

      def execute
        validate_args!

        Gitlab::Database::SharedModel.using_connection(connection) do
          if revert
            delete_migration
          else
            queue_migration
          end
        end
      end

      def allowed_gitlab_schemas
        [:gitlab_sec]
      end

      private

      def validate_args!
        unless /(\d+|instance)/.match?(namespace_id)
          warn "'#{namespace_id}' is not a number."
          warn 'Use `gitlab-rake \'gitlab:vulnerabilities:fix_auto_resolved_vulnerabilities[instance]\'` ' \
            'to perform an instance migration.'
          exit 1
        end

        return if instance_migration?

        namespace = Namespace.find_by_id(namespace_id)

        if namespace.blank?
          warn "Namespace:#{namespace_id} not found."
          exit 1
        end

        return if namespace.parent.blank?

        warn 'Namespace must be top-level.'
        exit 1
      end

      def queue_migration
        queue_batched_background_migration(
          MIGRATION,
          :vulnerability_reads,
          :vulnerability_id,
          job_args,
          gitlab_schema: :gitlab_sec
        )

        puts "Enqueued background migration: #{MIGRATION}, job_args: #{job_args}"
      end

      def delete_migration
        delete_batched_background_migration(MIGRATION, :vulnerability_reads, :vulnerability_id, [job_args])

        puts "Deleted background migration: #{MIGRATION}, job_args: #{job_args}"
      end

      def job_args
        if instance_migration?
          INSTANCE_ARG
        else
          namespace_id.to_i
        end
      end

      def instance_migration?
        namespace_id == INSTANCE_ARG
      end

      def version
        Time.now.utc.strftime("%Y%m%d%H%M%S")
      end

      def connection
        SecApplicationRecord.connection
      end
    end
  end
end
