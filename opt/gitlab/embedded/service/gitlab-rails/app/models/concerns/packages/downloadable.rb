# frozen_string_literal: true

module Packages
  module Downloadable
    extend ActiveSupport::Concern

    # last_downloaded_at is updated on every download. For popular packages this
    # produced a high volume of near-identical UPDATE statements. Only write when
    # the stored timestamp is older than THROTTLE_PERIOD, so repeat downloads within
    # the window match no row and perform no write.
    THROTTLE_PERIOD = 1.minute

    class_methods do
      # Stamps last_downloaded_at at most once per THROTTLE_PERIOD and skips the row when another
      # session holds its lock, so a download never waits on this bookkeeping write.
      #
      # @param id [Integer] the record id
      # @return [Integer] rows updated: 0 when throttled or the row was locked
      def touch_last_downloaded_at(id)
        column = arel_table[:last_downloaded_at]
        stale_condition = column.eq(nil).or(column.lt(THROTTLE_PERIOD.ago))

        ::Gitlab::Database::QueryAnalyzers::PreventWritesOnGet.allow_write_on_get(
          url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/608670') do
          ::Gitlab::Database::LoadBalancing::SessionMap.current(load_balancer).without_sticky_writes do
            # Skip this bookkeeping write instead of waiting on a held row lock until statement timeout.
            # SKIP LOCKED only skips conflicting row locks; the statement can still wait on
            # table-level locks, e.g. an ACCESS EXCLUSIVE from a concurrent migration.
            # NO KEY UPDATE, not FOR UPDATE, so FK checks from child-row inserts do not cause a skip.
            # Keep the outer id filter: Postgres does not flatten locked subqueries, so it keeps the PK scan.
            candidates = id_in(id).where(stale_condition).select(:id).lock('FOR NO KEY UPDATE SKIP LOCKED')

            id_in(id).where(id: candidates).update_all(last_downloaded_at: Time.zone.now)
          end
        end
      end
    end

    def touch_last_downloaded_at
      # The record is already loaded here, so short-circuit on the in-memory value
      # to avoid issuing a query at all when the timestamp is already fresh.
      return if last_downloaded_at && last_downloaded_at > THROTTLE_PERIOD.ago

      self.class.touch_last_downloaded_at(id)
    end
  end
end

Packages::Downloadable.prepend_mod
Packages::Downloadable::ClassMethods.prepend_mod
