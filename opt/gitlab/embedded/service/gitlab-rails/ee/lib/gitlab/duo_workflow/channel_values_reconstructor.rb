# frozen_string_literal: true

module Gitlab
  module DuoWorkflow
    # Rebuilds a checkpoint's channel_values from incremental checkpoint blobs.
    # Each blob is a per-step delta (zlib-compressed JSON) for one (channel,
    # version); step_action carries the reducer signal -- a compaction replaces,
    # anything else appends. Pass blobs from a single ancestor chain (see
    # Ai::DuoWorkflows::Workflow#accumulated_blobs_for); off-chain blobs derive
    # from a different base and must not be mixed in.
    class ChannelValuesReconstructor
      include ::Gitlab::Utils::StrongMemoize

      COMPACTION = 'compaction'
      CONVERSATION = 'conversation'
      USER_MESSAGE = 'user'
      MESSAGE_ID = 'message_id'
      MESSAGE_TYPE = 'message_type'

      CorruptBlobError = Class.new(StandardError)

      # Decode a single blob's `data` (zlib-compressed JSON) to its Ruby value.
      # Exposed so callers that need just one blob (e.g. the tail of a channel)
      # can decode without instantiating a full reconstruction. Corruption isn't
      # expected (our gateway writes valid zlib JSON); raise rather than skip, so
      # a bad blob fails the read instead of returning inconsistent values.
      def self.decode(data)
        parse_json(Zlib::Inflate.inflate(data))
      rescue Zlib::Error
        raise CorruptBlobError, 'Failed to decode checkpoint blob'
      end

      # Parse an inflated blob, raising CorruptBlobError like .decode.
      def self.parse_json(json)
        ::Gitlab::Json.safe_parse(json)
      rescue JSON::ParserError
        raise CorruptBlobError, 'Failed to decode checkpoint blob'
      end

      # The key #unseen_entries dedups snapshot entries by. An approval request and
      # its tool result share the tool call id as message_id, so the id alone would
      # drop the result as a repeat of the request
      # (https://gitlab.com/gitlab-org/gitlab/-/work_items/629915).
      def self.entry_key(entry)
        return unless entry.is_a?(Hash) && entry[MESSAGE_ID]

        [entry[MESSAGE_ID], entry[MESSAGE_TYPE]]
      end

      # `decoded` caches each blob's decoded value for #channel_values. Pass one
      # Hash to every reconstructor of a page so each blob is decoded once.
      def initialize(blobs, decoded: {})
        @blobs = blobs
        @decoded = decoded
      end

      def channel_values
        blobs_by_channel.keys.index_with { |channel| fold(channel) }
      end

      # Build one channel's FULL history for display. Unlike #channel_values, which
      # anchors at the last compaction to rebuild agent state, this keeps every
      # conversation delta. From a mid-stream compaction snapshot it takes only the
      # entries not already in the history (see #unseen_entries): a restart re-seed
      # repeats known entries and adds nothing, while a compaction's summary card is
      # new and is kept. A snapshot seeds the base when there is no list history yet:
      # the earliest one, or one after a delta replaced the history. A snapshot that
      # starts with the previous one is parsed only past it (see SnapshotParser). Pass
      # blobs from the full ancestor chain across all groups (Workflow#history_blobs_for).
      #
      # `ancestry` maps thread_ts -> parent_ts for that chain; every entry is stamped
      # with the checkpoint that introduced it (see #stamp).
      #
      # `from` resumes a history an earlier call built from a prefix of the chain's
      # blobs; pass only the blobs after that prefix. A retry since then can change
      # the alternative counts, so they are re-applied to `from`.
      def channel_history(channel, ancestry, alternatives, from: nil)
        count_alternatives(from, alternatives)
        snapshots = SnapshotParser.new
        seen_ids = SeenMessageIds.new

        # Prefer the conversation delta: it stays a delta even when the snapshot is
        # trimmed, so it never depends on the snapshot lining up with the fold.
        ordered_blobs_for(channel, prefer: CONVERSATION).reduce(from) do |history, blob|
          # A replaced history dropped the previous snapshot's entries, so parse them again.
          snapshots.reset unless history.is_a?(Array)
          next append(history, stamp(decode(blob.data), blob, ancestry, alternatives)) if blob.step_action != COMPACTION

          entries = snapshots.parse(blob.data)
          next stamp(entries, blob, ancestry, alternatives) unless history.is_a?(Array)

          # Stamp only the new entries: the rest of the snapshot is dropped, and a
          # snapshot is the largest blob we read.
          added = unseen_entries(history, entries, seen_ids)
          added.empty? ? history : history.concat(stamp(added, blob, ancestry, alternatives))
        end
      end

      # Every value a channel took over the session, oldest first, so plan and status
      # changes stay visible instead of collapsing to a single value. Pass blobs from the
      # full ancestor chain across all groups (Workflow#accumulated_blobs_for).
      #
      # Three shapes share this path, told apart by each decoded value rather than by the
      # channel, because a channel can start nil before it holds a list or a dict:
      #
      # - A list records each change as a delta, so a mid-stream compaction mostly repeats
      #   entries the deltas already carry. We keep only the entries it adds (see
      #   #unseen_entries), which is what the compaction-triggering step wrote.
      # - A dict snapshot is the full replacement the gateway writes for a `plan` step edit
      #   or a `last_human_input` key-set change. Keeping it would re-record the whole
      #   channel per edit, so the trace reports appends only.
      # - A scalar (status, goal) has no delta form -- the gateway writes every value as a
      #   full replacement -- so each blob is a real transition, bar one that repeats the
      #   value before it, which is a group re-seed rather than a change.
      def channel_changes(channel)
        # Prefer the conversation delta: a colliding compaction carries the whole channel,
        # so the delta is the more precise record of that version's change.
        ordered = ordered_blobs_for(channel, prefer: CONVERSATION)
        dict = false

        ordered.each_with_index.each_with_object([]) do |(blob, index), changes|
          snapshot = blob.step_action == COMPACTION && index > 0
          # A dict snapshot is dropped whatever it holds, and each one is as large as the
          # whole channel, so skip it before decoding.
          next if snapshot && dict

          value = decode(blob.data)

          case value
          when Array
            changes.concat(snapshot ? unseen_entries(changes, value) : value)
          when Hash
            dict = true
            next if snapshot

            changes.push(value)
          else
            changes.push(value) if changes.empty? || changes.last != value
          end
        end
      end

      # thread_ts -> the value a scalar channel held at that checkpoint. A scalar blob
      # carries the whole value, so there is nothing to fold; the work is picking one
      # row per checkpoint. Prefer the compaction.
      def scalar_values_by_thread_ts(channel)
        ordered_blobs_for(channel, prefer: COMPACTION)
          .to_h { |blob| [blob.thread_ts, decode(blob.data)] }
      end

      private

      # Anchor at the last compaction so the fold is O(deltas since it), not
      # O(chain length); safe only for a single ancestor chain (see #initialize).
      # Prefer the compaction: it carries the full value, so anchoring on it keeps
      # the fold short.
      def fold(channel)
        ordered = ordered_blobs_for(channel, prefer: COMPACTION)

        last_compaction = ordered.rindex { |blob| blob.step_action == COMPACTION }
        ordered = ordered.drop(last_compaction) if last_compaction

        ordered.reduce(nil) { |value, blob| apply(value, blob) }
      end

      # Blobs come in chain order (id order, see Workflow#accumulated_blobs_for), not
      # version order, because version numbers can repeat after a compaction resets the
      # writer's counter. group_by keeps each version at its first occurrence, so no sort.
      def ordered_blobs_for(channel, prefer:)
        # Dedup by thread_ts and version together, not version alone. A version can repeat
        # legitimately across thread groups, and grouping by version alone would drop it.
        blobs_by_channel.fetch(channel, [])
          .group_by { |blob| [blob.thread_ts, blob.version] }
          .values
          # A force_rewrite can store both a delta and a compaction under the same version.
          # `prefer` picks the winning step_action, so the result never depends on insertion
          # order (https://gitlab.com/gitlab-org/gitlab/-/issues/604371).
          .map { |rows| rows.find { |blob| blob.step_action == prefer } || rows.first }
      end

      # Memoized: one group_by(&:channel) pass covers all channels, not a rescan per channel.
      def blobs_by_channel
        @blobs.group_by(&:channel)
      end
      strong_memoize_attr :blobs_by_channel

      # A compaction replaces the running value; anything else appends. Other
      # reconstructors may share the decoded value, and #append grows the running
      # value in place, so fold a copy.
      def apply(value, blob)
        delta = copy(decoded(blob))
        return delta if blob.step_action == COMPACTION

        append(value, delta)
      end

      def decoded(blob)
        @decoded.fetch(blob) { @decoded[blob] = decode(blob.data) }
      end

      def copy(value)
        case value
        when Array then value.dup
        when Hash then value.transform_values { |field| field.is_a?(Array) ? field.dup : field }
        else value
        end
      end

      # Snapshot entries not yet in `history`, the messages collected so far. A snapshot
      # may repeat the whole log (a restart re-seed) or hold only the summary card and
      # its own step's entries (a trimmed log), so match by #entry_key, not by prefix.
      # The compaction-triggering step writes no conversation delta of its own
      # (https://gitlab.com/gitlab-org/gitlab/-/issues/619495), so this is the only
      # place its entries can come from. Pass the fold's SeenMessageIds to reuse the
      # keys indexed by earlier snapshots.
      def unseen_entries(history, snapshot, seen_ids = SeenMessageIds.new)
        return [] unless history.is_a?(Array) && snapshot.is_a?(Array)

        keys = seen_ids.of(history)

        snapshot.reject do |entry|
          key = entry_key(entry)
          key ? keys.include?(key) : history.any? { |seen| same_entry?(seen, entry) }
        end
      end

      def entry_key(entry)
        self.class.entry_key(entry)
      end

      # #stamp adds keys to the accumulated entries, so match on the snapshot's own
      # fields rather than comparing the entries whole.
      def same_entry?(entry, other)
        return other.all? { |key, field| entry[key] == field } if entry.is_a?(Hash) && other.is_a?(Hash)

        entry == other
      end

      # Append `delta` onto the running `value` in place. Shared by #fold (agent
      # state) and #channel_history (display) so both grow lists identically.
      def append(value, delta)
        case delta
        when Array
          # concat (not +) so folding k appends is O(k), not O(k^2); the running
          # value is never shared (see #apply), so growing it in place is safe.
          value ? value.concat(delta) : delta
        when Hash
          # dict-of-list channel: append each key's tail to the accumulated list.
          return delta unless value.is_a?(Hash)

          delta.each do |key, tail|
            if tail.is_a?(Array)
              (value[key] ||= []).concat(tail)
            else
              value[key] = tail
            end
          end
          value
        else
          delta
        end
      end

      # Stamp each message with the checkpoint that introduced it: the blob's own
      # thread_ts and that checkpoint's parent_ts -- the point a client forks from.
      def stamp(value, blob, ancestry, alternatives)
        return value unless value.is_a?(Array)

        value.each do |entry|
          next unless entry.is_a?(Hash)

          entry['thread_ts'] = blob.thread_ts
          entry['parent_ts'] = ancestry[blob.thread_ts]
        end
        count_alternatives(value, alternatives)
      end

      # A user message anchors its turn, so it carries the alternative count of the
      # checkpoint #stamp recorded on it.
      def count_alternatives(history, alternatives)
        return history unless history.is_a?(Array)

        history.each do |entry|
          next unless entry.is_a?(Hash) && entry['message_type'] == USER_MESSAGE

          entry['alternative_count'] = alternatives.fetch(entry['thread_ts'], 0)
        end
      end

      def decode(data)
        self.class.decode(data)
      end

      # Parses the snapshots of one #channel_history fold, oldest first. A group-start
      # snapshot repeats the previous one and appends to it, so when its text starts
      # with the previous snapshot's entries, only the entries after them are parsed.
      # Those skipped entries are already in the history, so #unseen_entries would
      # drop them anyway. Inflates into two reused buffers.
      class SnapshotParser
        COMMA = ','.ord

        def initialize
          # Binary like .decode's input: the validator rejects a UTF-8 string with invalid bytes.
          @current = ''.b
          @previous = ''.b
          @extendable = false
        end

        # The snapshot's entries, or only those after the previous snapshot's entries.
        def parse(data)
          inflate(data)
          tail = appended_entries_json
          entries = ChannelValuesReconstructor.parse_json(tail || @current)
          # Keep a non-empty array's entries, without the closing "]", to compare the next snapshot.
          @extendable = @current.end_with?(']') && (tail.present? || (entries.is_a?(Array) && entries.present?))
          @current.chop! if @extendable
          @current, @previous = @previous, @current
          entries
        end

        # Parse the next snapshot whole.
        def reset
          @extendable = false
        end

        private

        def inflate(data)
          zstream = Zlib::Inflate.new
          begin
            zstream.inflate(data, buffer: @current)
            # Not #finish: after inflate(buffer:) it returns an invalid object (segfault, zlib gem 3.2.3).
            raise CorruptBlobError, 'Failed to decode checkpoint blob' unless zstream.finished?
          ensure
            zstream.close
          end
        rescue Zlib::Error
          raise CorruptBlobError, 'Failed to decode checkpoint blob'
        end

        # A JSON array of the entries after the previous snapshot's, or nil when the
        # snapshot does not extend the previous one.
        def appended_entries_json
          return unless @extendable && @current.end_with?(']') && @current.start_with?(@previous)

          rest = @current.bytesize - @previous.bytesize
          return '[]' if rest == 1
          return unless @current.getbyte(@previous.bytesize) == COMMA

          # Stop before the closing "]": a slice that reaches the end shares the buffer,
          # and changing the buffer would then copy it.
          appended = @current.byteslice(@previous.bytesize + 1, rest - 2)
          # Nothing after the comma is malformed, so parse it whole to raise.
          "[#{appended}]" if appended.match?(/\S/)
        end
      end
      private_constant :SnapshotParser

      # Entry keys (see .entry_key) already in a history. Until #append replaces it, the
      # history only grows in place, so each call indexes only the entries added since
      # the last one.
      class SeenMessageIds
        def of(history)
          unless history.equal?(@history)
            @history = history
            @ids = Set.new
            @indexed = 0
          end

          history.drop(@indexed).each do |entry|
            key = ChannelValuesReconstructor.entry_key(entry)
            @ids << key if key
          end
          @indexed = history.size
          @ids
        end
      end
      private_constant :SeenMessageIds
    end
  end
end
