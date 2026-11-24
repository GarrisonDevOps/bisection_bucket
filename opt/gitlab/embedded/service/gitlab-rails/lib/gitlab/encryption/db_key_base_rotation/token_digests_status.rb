# frozen_string_literal: true

module Gitlab
  module Encryption
    module DbKeyBaseRotation
      # Misses a token whose rehash failed on its last use since the rotation.
      class TokenDigestsStatus
        include Gitlab::Utils::StrongMemoize

        BATCH_SIZE = 1_000

        Result = Struct.new(:model, :remaining, :expired, :without_expiry, :latest_expiry, keyword_init: true)

        # rotated_at: when the last node switched keys, plus the rehash lease timeout.
        def initialize(rotated_at:)
          unless rotated_at.is_a?(Time) && rotated_at <= Time.current
            raise ArgumentError, 'rotated_at must not be in the future'
          end

          @rotated_at = rotated_at
        end

        def execute
          token_relations.map { |relation| result_for(relation) }
        end
        strong_memoize_attr :execute

        # Expired tokens don't count, so their expiry must not be extended afterwards.
        def retirement_date
          return if execute.any? { |result| result.without_expiry > 0 }

          [Date.current, *execute.filter_map { |result| result.latest_expiry&.next_day }].max
        end

        private

        attr_reader :rotated_at

        def token_relations
          [PersonalAccessToken.not_revoked]
        end

        def result_for(relation)
          # rubocop:disable CodeReuse/ActiveRecord -- one-off rotation status query
          remaining = relation
            .where(created_at: ..rotated_at)
            .where(relation.arel_table[:last_used_at].eq(nil).or(relation.arel_table[:last_used_at].lteq(rotated_at)))
          # rubocop:enable CodeReuse/ActiveRecord

          totals = { remaining: 0, expired: 0, without_expiry: 0, latest_expiry: nil }

          relation.klass.each_batch(of: BATCH_SIZE) do |batch|
            totals.merge!(counts_for(batch.merge(remaining), expires: expires?(relation))) do |key, total, count|
              key == :latest_expiry ? [total, count].compact.max : total + count
            end
          end

          Result.new(model: relation.klass.name, **totals)
        end

        def counts_for(batch, expires:)
          unless expires
            count = batch.count
            return { remaining: count, expired: 0, without_expiry: count, latest_expiry: nil }
          end

          remaining, expired, without_expiry, latest_expiry = batch.pick(
            Arel.sql('COUNT(*) FILTER (WHERE expires_at IS NULL OR expires_at > NOW())'),
            Arel.sql('COUNT(*) FILTER (WHERE expires_at <= NOW())'),
            Arel.sql('COUNT(*) FILTER (WHERE expires_at IS NULL)'),
            Arel.sql('MAX(expires_at)')
          )

          { remaining: remaining, expired: expired, without_expiry: without_expiry, latest_expiry: latest_expiry }
        end

        def expires?(relation)
          relation.klass.column_names.include?('expires_at')
        end
      end
    end
  end
end

Gitlab::Encryption::DbKeyBaseRotation::TokenDigestsStatus.prepend_mod
