# frozen_string_literal: true

module Gitlab
  module Graphql
    module Subscriptions
      # What `ActionCableWithLoadBalancing` broadcasts: the payload with the WAL locations and the correlation ID
      # of the process that triggered it.
      class Envelope
        KEY_PAYLOAD = 'gql_payload'
        KEY_WAL_LOCATIONS = 'wal_locations'
        KEY_CORRELATION_ID = 'correlation_id'
        GLOBALID_KEY = ::GraphQL::Subscriptions::Serialize::GLOBALID_KEY

        def self.wrap(payload, wal_locations:, correlation_id:)
          new(KEY_WAL_LOCATIONS => wal_locations, KEY_CORRELATION_ID => correlation_id, KEY_PAYLOAD => payload)
        end

        # Reads a raw broadcast without resolving any global ID, so it runs no database query. Returns nil for a
        # message that is not an envelope, and an unreadable envelope for one that cannot be parsed.
        def self.parse(message)
          raw = ::Gitlab::Json::SafeParser.parse(message)
          new(raw) if wrapped?(raw)
        rescue ::JSON::ParserError
          new({})
        end

        # A process that does not wrap its broadcasts yet, during a deploy, sends the payload alone.
        def self.wrapped?(object)
          object.try(:key?, KEY_PAYLOAD)
        end

        # The coalescer's merge. Only envelopes merge: `Hash#merge` would drop the WAL location rules silently.
        def self.merge(older, newer)
          raise ArgumentError, 'both updates must be envelopes' unless older.is_a?(self) && newer.is_a?(self)

          older.merge(newer)
        end

        def initialize(raw)
          @raw = raw
        end

        def to_h
          @raw
        end

        def readable?
          self.class.wrapped?(@raw)
        end

        def payload
          @raw[KEY_PAYLOAD]
        end

        def wal_locations
          @raw[KEY_WAL_LOCATIONS]
        end

        def correlation_id
          @raw[KEY_CORRELATION_ID]
        end

        # Only an update about one record can be merged with the next update about the same record.
        def record_id
          payload[GLOBALID_KEY] if payload.try(:keys) == [GLOBALID_KEY]
        end

        # Keeps the newer payload with the newest WAL location of each database from both, so a replica that
        # has not caught up with the older update cannot serve an older state after it. Updates arrive from
        # many processes, so the newest one to arrive does not always carry the newest locations.
        def merge(newer)
          self.class.new(newer.to_h.merge(KEY_WAL_LOCATIONS => merged_locations(newer)))
        end

        private

        # Blank or unreadable locations make the update read from the primary. Keep that.
        def merged_locations(newer)
          older_lsns = lsns(wal_locations)
          newer_lsns = lsns(newer.wal_locations)
          return {} unless older_lsns && newer_lsns

          older_lsns.merge(newer_lsns) { |_db, old, new| [old, new].max }.transform_values(&:to_s)
        end

        # Parses each location once. Nil when there are none, or when one of them is unreadable.
        def lsns(locations)
          parsed = locations.to_h.transform_values { |text| ::Gitlab::Database::LoadBalancing::Lsn.parse(text) }

          parsed if parsed.any? && parsed.values.all?
        end
      end
    end
  end
end
