# frozen_string_literal: true

module Gitlab
  module Database
    module PgAsh
      # Applies, removes and inspects the vendored pg_ash install script.
      #
      # Re-applying the same vendored version is a no-op and is safe, but upstream ships a
      # separate migration chain for moving between versions, and that chain is
      # not vendored currently (to be added in future releases).
      # #install therefore refuses to run over a different installed version.
      #
      # Targets the main database only. Support for ci and sec
      # depends on telling co-located databases apart, because pg_stat_activity
      # is cluster-wide: https://gitlab.com/gitlab-org/gitlab/-/issues/608099
      class Installer
        PermissionError = Class.new(StandardError)
        VersionMismatchError = Class.new(StandardError)

        # take_sample() runs as the calling role. Stock PostgreSQL lets every role read
        # pg_stat_activity, but a hardened cluster can revoke it, and then every sample fails.
        PG_STAT_ACTIVITY_READABLE_QUERY = <<~SQL.squish.freeze
          SELECT
            has_table_privilege('pg_catalog.pg_stat_activity', 'SELECT')
            AND has_function_privilege('pg_catalog.pg_stat_get_activity(integer)', 'EXECUTE')
        SQL

        # Without the privileges of pg_read_all_stats, other users' sessions have a NULL state,
        # and take_sample() skips them. USAGE, not MEMBER: a grant WITH INHERIT FALSE hides them too.
        ALL_SESSIONS_VISIBLE_QUERY = "SELECT pg_has_role('pg_read_all_stats', 'USAGE')"

        def initialize(connection = ApplicationRecord.connection)
          @connection = connection
        end

        # @return [String] the version now stamped in ash.config
        def install
          current = installed_version
          raise VersionMismatchError, version_mismatch_message(current) if current && current != VENDORED_VERSION

          error = sampling_error
          raise PermissionError, error if error

          execute(PgAsh.install_sql)

          installed_version
        rescue ActiveRecord::StatementInvalid => e
          raise unless e.cause.is_a?(PG::InsufficientPrivilege)

          raise PermissionError, permission_denied_message
        end

        # @return [String, nil] why every sample fails, or nil when the user can read pg_stat_activity
        def sampling_error
          pg_stat_activity_denied_message unless pg_stat_activity_readable?
        end

        # @return [String, nil] why samples will miss sessions, or nil when every session is sampled
        def sampling_warning
          limited_visibility_message unless all_sessions_visible?
        end

        # @return [Boolean] false when pg_ash was not installed to begin with
        def uninstall
          return false unless installed?

          execute("SELECT #{PgAsh::SCHEMA_NAME}.uninstall('yes')")

          true
        end

        # @return [Hash, nil] metric => value, or nil when pg_ash is not installed
        def status
          return unless installed?

          execute("SELECT metric, value FROM #{PgAsh::SCHEMA_NAME}.status()")
            .to_h { |row| [row['metric'], row['value']] }
        end

        def installed?
          connection.schema_exists?(PgAsh::SCHEMA_NAME)
        end

        def installed_version
          return unless installed?

          execute("SELECT version FROM #{PgAsh::SCHEMA_NAME}.config WHERE singleton").first&.fetch('version')
        end

        private

        attr_reader :connection

        def execute(sql)
          PgAsh.execute(connection, sql)
        end

        def pg_stat_activity_readable?
          connection.select_value(PG_STAT_ACTIVITY_READABLE_QUERY)
        end

        def all_sessions_visible?
          connection.select_value(ALL_SESSIONS_VISIBLE_QUERY)
        end

        def version_mismatch_message(current)
          <<~MSG
            pg_ash #{current} is installed, but this GitLab vendors #{VENDORED_VERSION}.

            The vendored script installs pg_ash; it does not upgrade an existing
            install. To move to #{VENDORED_VERSION}, either:

              * run gitlab:db:pg_ash:uninstall first, which drops the
                '#{PgAsh::SCHEMA_NAME}' schema and every sample collected so far, then
                run this task again, or
              * apply the upstream migration chain by hand. See
                https://github.com/NikolayS/pg_ash/tree/main/sql/migrations
          MSG
        end

        def permission_denied_message
          database = ApplicationRecord.database

          <<~MSG
            Installing pg_ash creates the '#{PgAsh::SCHEMA_NAME}' schema in database
            '#{database.database_name}', but user '#{database.username}' is not allowed to create it.

            Grant the privilege using a database superuser:

                GRANT CREATE ON DATABASE #{database.database_name} TO #{database.username};

            Then run this task again. The install script is idempotent, so it is
            safe to re-apply after a failure.
          MSG
        end

        def pg_stat_activity_denied_message
          database = ApplicationRecord.database

          <<~MSG
            pg_ash samples pg_stat_activity as user '#{database.username}', but that user is not
            allowed to read it in database '#{database.database_name}'. Every sample fails
            with "permission denied for view pg_stat_activity".

            Grant the privileges using a database superuser:

                GRANT SELECT ON pg_catalog.pg_stat_activity TO #{database.username};
                GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_get_activity(integer) TO #{database.username};

            Then run this task again.
          MSG
        end

        def limited_visibility_message
          username = ApplicationRecord.database.username

          <<~MSG
            pg_ash samples only the sessions of user '#{username}'. That user cannot see what the
            sessions of other database users are doing, such as a console session or a superuser
            session that holds a lock.

            To sample every session, grant pg_read_all_stats using a database superuser:

                GRANT pg_read_all_stats TO #{username};

            pg_read_all_stats also lets '#{username}' read the queries and statistics of every
            database user.
          MSG
        end
      end
    end
  end
end
