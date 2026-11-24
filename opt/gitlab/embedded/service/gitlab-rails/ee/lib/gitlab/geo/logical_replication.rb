# frozen_string_literal: true

module Gitlab
  module Geo
    class LogicalReplication
      ActiveSubscriptionError = Class.new(StandardError)

      # pg_subscription is readable by unprivileged users. Only subconninfo (the connection string)
      # is restricted, which we don't select here. pg_subscription is a cluster-wide catalog, so it
      # is filtered down to the database the connection is pointing at.
      SUBSCRIPTION_NAMES_SQL = <<~SQL
        SELECT s.subname
        FROM pg_catalog.pg_subscription s
        JOIN pg_catalog.pg_database d ON d.oid = s.subdbid
        WHERE d.datname = current_database()
      SQL

      # This is a singleton class that allows to query the state of replication on a Geo secondary
      class << self
        include Gitlab::Utils::StrongMemoize

        def active?
          configured? && database_subscribed?
        end

        # Logical replication is the transport actually in use on this site: it is configured, and
        # the database is writable rather than a PostgreSQL standby being fed streaming replication.
        def in_use?
          configured? && !ApplicationRecord.database.recovery?
        end

        # The database behind connection is fed by logical replication: a writable database on a Geo secondary.
        # Unlike in_use?, it ignores the feature flag, since the partition maintenance it guards has to follow the
        # database, and it reads a fresh GeoNode so a promoted site stops counting without a restart.
        def subscriber?(connection)
          # geo_nodes arrives through the subscription, so a subscriber still in its initial copy has no node yet
          node = ::GeoNode.current_node if ::Gitlab::Geo.enabled?
          replicated = node ? node.secondary? : subscription_names(connection).any?

          # Asks the given connection, not ApplicationRecord.database. A streaming standby is read-only.
          replicated && !::Gitlab::Utils.to_boolean(connection.select_value('SELECT pg_is_in_recovery()'))
        end

        def configured?
          Gitlab::Geo.secondary? && Gitlab::Geo.postgresql_replication_agnostic_enabled?
        end

        def database_subscribed?
          # rubocop:disable Gitlab/StrongMemoizeAttr -- rescue must be outside the memoized block
          # so transient or fixable failures are retried rather than permanently memoized
          # Note that to enable LR users must Rails and Sidekiq, so it is safe to memoize this method
          # in this singleton class (once per process)
          strong_memoize(:database_subscribed) do
            subscription_names.any?
          end
        rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished,
          ActiveRecord::ConnectionFailed => e
          # not memoized as the failures can be recovered from without a Rails restart by addressing the database
          # configuration issues directly
          Gitlab::Geo::Logger.error(
            message: "database_subscribed? failed",
            error_class: e.class.name,
            error_message: e.message
          )
          false
        end
        # rubocop:enable Gitlab/StrongMemoizeAttr

        def ensure_no_active_subscription!
          subscriptions = active_subscriptions
          return if subscriptions.empty?

          found = subscriptions.map { |db_name, names| "#{db_name}: #{names.join(', ')}" }.join('; ')

          raise ActiveSubscriptionError, <<~ERROR.squish
            Logical replication subscriptions are still present (#{found}). Drop them with
            gitlab:geo:logical_replication:subscription:drop before promoting, which first checks that
            the subscriber has caught up (ALTER SUBSCRIPTION ... DISABLE is not sufficient: a disabled
            subscription can be re-enabled and apply rows with higher IDs after the sequences have been synced).
          ERROR
        end

        # Deliberately not memoized: promotion re-reads this after syncing sequences, so a cached
        # answer would turn that second check into a no-op.
        def active_subscriptions
          {}.tap do |result|
            Gitlab::Database::EachDatabase.each_connection(include_shared: false) do |connection, db_name|
              names = subscription_names(connection)

              result[db_name] = names if names.any?
            end
          end
        end

        # Errors are not rescued here: callers gating a promotion need a failed read to abort rather
        # than to look like an absence of subscriptions.
        def subscription_names(connection = ApplicationRecord.connection)
          connection.select_values(SUBSCRIPTION_NAMES_SQL)
        end
      end
    end
  end
end
