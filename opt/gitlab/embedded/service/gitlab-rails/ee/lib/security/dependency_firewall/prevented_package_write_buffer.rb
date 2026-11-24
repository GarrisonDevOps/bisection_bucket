# frozen_string_literal: true

module Security
  module DependencyFirewall
    # Two-phase drain like ActivityStatWriteBuffer, but the merge operation is element-wise
    # min/max on timestamps rather than a counter increment: one hash field per ledger key
    # (project, rule type, identifier), value "first:blocked:warned:severity" as epoch-second
    # integers with 0 meaning absent. Merging keeps min(first) and max(blocked/warned/severity),
    # so replays and out-of-order adds can only converge, never regress - at-least-once safe.
    class PreventedPackageWriteBuffer < ::Analytics::DatabaseWriteBuffer
      SEPARATOR = ':'
      ABSENT = 0

      # Merges one entry into a hash field. cjson is avoided: values are four ints.
      LUA_MERGE_INTO = <<~LUA
        local key, field = KEYS[1], ARGV[1]
        local f, b, w, s = tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5])
        local cur = redis.call('HGET', key, field)
        if cur then
          local cf, cb, cw, cs = string.match(cur, '(%d+):(%d+):(%d+):(%d+)')
          f = math.min(f, tonumber(cf))
          b = math.max(b, tonumber(cb))
          w = math.max(w, tonumber(cw))
          s = math.max(s, tonumber(cs))
        end
        redis.call('HSET', key, field, f .. ':' .. b .. ':' .. w .. ':' .. s)
      LUA

      # Stages the live hash by max-merging every field into the staged hash.
      LUA_STAGE_SCRIPT = <<~LUA
        local live, staged = KEYS[1], KEYS[2]
        local entries = redis.call('HGETALL', live)
        for i = 1, #entries, 2 do
          local field, value = entries[i], entries[i + 1]
          local f, b, w, s = string.match(value, '(%d+):(%d+):(%d+):(%d+)')
          local cur = redis.call('HGET', staged, field)
          if cur then
            local cf, cb, cw, cs = string.match(cur, '(%d+):(%d+):(%d+):(%d+)')
            f = math.min(tonumber(f), tonumber(cf))
            b = math.max(tonumber(b), tonumber(cb))
            w = math.max(tonumber(w), tonumber(cw))
            s = math.max(tonumber(s), tonumber(cs))
          end
          redis.call('HSET', staged, field, f .. ':' .. b .. ':' .. w .. ':' .. s)
        end
        redis.call('DEL', live)
        redis.call('PERSIST', staged)
      LUA

      # Deletes a staged field only when its value is unchanged since it was read, so a merge
      # that landed after the flush read survives for the next run.
      LUA_REMOVE_STAGED_SCRIPT = <<~LUA
        local staged = KEYS[1]
        for i = 1, #ARGV, 2 do
          if redis.call('HGET', staged, ARGV[i]) == ARGV[i + 1] then
            redis.call('HDEL', staged, ARGV[i])
          end
        end
      LUA

      Entry = Struct.new(:project_id, :rule_type, :identifier, :first_seen_at, :last_blocked_at,
        :last_warned_at, :severity, :raw_field, :raw_value, keyword_init: true) do
        def to_row
          {
            project_id: project_id,
            rule_type: rule_type,
            identifier: identifier,
            first_seen_at: first_seen_at,
            last_blocked_at: last_blocked_at,
            last_warned_at: last_warned_at,
            severity: severity
          }
        end
      end

      def add(attributes)
        raise ArgumentError, 'expects a single entry hash' if attributes.is_a?(Array)

        field = field_for(attributes)
        now = attributes.fetch(:seen_at).utc.to_i
        severity = attributes[:severity]

        argv = [
          field,
          now,
          attributes[:blocked] ? now : ABSENT,
          attributes[:warned] ? now : ABSENT,
          severity.nil? ? ABSENT : Integer(severity)
        ]

        Gitlab::Redis::SharedState.with do |redis|
          redis.eval(LUA_MERGE_INTO, keys: [buffer_key], argv: argv)
        end
      end

      def pop(_limit)
        raise NotImplementedError, 'entries are hash-shaped; stage! then staged_batch'
      end

      def stage!
        Gitlab::Redis::SharedState.with do |redis|
          redis.eval(LUA_STAGE_SCRIPT, keys: [buffer_key, staged_key])
        end
      end

      # HSCAN keeps each call proportional to the page, not the backlog. COUNT is only a hint, so a
      # page can exceed limit. A field HSCAN repeats is dropped within a page (one upsert cannot touch
      # a row twice) and harmless across pages (the merge is idempotent).
      #
      # @param limit [Integer] the COUNT hint
      # @param cursor [String] "0" to start, then the cursor returned by the previous call
      # @return [Array(Array<Entry>, String)] the page's entries, and the cursor to resume from or "0" when done
      def staged_batch(limit, cursor = '0')
        Gitlab::Redis::SharedState.with do |redis|
          next_cursor, pairs = redis.hscan(staged_key, cursor, count: limit)

          [pairs.uniq(&:first).map { |field, value| entry_for(field, value) }, next_cursor]
        end
      end

      def staged_size
        Gitlab::Redis::SharedState.with { |redis| redis.hlen(staged_key) }
      end

      def live_size
        Gitlab::Redis::SharedState.with { |redis| redis.hlen(buffer_key) }
      end

      def remove_staged(entries)
        return if entries.empty?

        argv = entries.flat_map { |entry| [entry.raw_field, entry.raw_value] }

        Gitlab::Redis::SharedState.with do |redis|
          redis.eval(LUA_REMOVE_STAGED_SCRIPT, keys: [staged_key], argv: argv)
        end
      end

      private

      # Hash tag co-locates this with staged_key; RedisClusterValidator does not check EVAL.
      def buffer_key
        "{#{super}}"
      end

      def staged_key
        "#{buffer_key}:staged"
      end

      # Identifier goes last so its own separators survive a bounded split on read.
      def field_for(attributes)
        [
          attributes.fetch(:project_id),
          # Integer() so an enum key like 'malicious' raises instead of reading back as 0 (license).
          Integer(attributes.fetch(:rule_type)),
          attributes.fetch(:identifier)
        ].join(SEPARATOR)
      end

      def entry_for(field, value)
        project_id, rule_type, identifier = field.split(SEPARATOR, 3)
        first, blocked, warned, severity = value.split(SEPARATOR).map(&:to_i)

        Entry.new(
          project_id: project_id.to_i,
          rule_type: rule_type.to_i,
          identifier: identifier,
          first_seen_at: Time.zone.at(first).utc,
          last_blocked_at: blocked == ABSENT ? nil : Time.zone.at(blocked).utc,
          last_warned_at: warned == ABSENT ? nil : Time.zone.at(warned).utc,
          severity: severity == ABSENT ? nil : severity,
          raw_field: field,
          raw_value: value
        )
      end
    end
  end
end
