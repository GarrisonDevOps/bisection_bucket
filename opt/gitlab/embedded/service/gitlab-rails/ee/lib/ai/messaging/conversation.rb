# frozen_string_literal: true

module Ai
  module Messaging
    # A rendered conversation (newest last) plus its marker policy. The marker
    # callable receives the dropped count for every candidate -- including
    # zero -- and returns the marker string, or nil for no marker.
    class Conversation < Data.define(:messages, :marker)
      def to_s
        assemble(messages, 0)
      end

      # Largest run of newest messages that fits, marker measured within the
      # limit. Returns nil when not even the newest message fits.
      def keep_newest_within(limit)
        full = to_s
        return full if full.length <= limit

        best = nil

        (messages.length - 1).downto(1) do |dropped|
          candidate = assemble(messages[dropped..], dropped)
          break if candidate.length > limit

          best = candidate
        end

        best
      end

      # Shrinks until the wrapped render fits: yields '' once to measure the
      # exact render overhead, then the fitted conversation. Returns the wrapped
      # render and the fitted conversation it was built from, so callers can
      # re-wrap it. on_overflow fires with (wrapped_length, overhead) only when
      # the re-render still overflows.
      def render_within(limit, on_overflow: nil)
        overhead = yield('').to_s.length
        fitted = keep_newest_within(limit - overhead)
        return if fitted.nil?

        wrapped = yield(fitted)
        return wrapped, fitted if wrapped && wrapped.length <= limit

        on_overflow&.call(wrapped&.length, overhead)
        nil
      end

      private

      def assemble(included, dropped)
        [marker.call(dropped), *included].compact.join("\n")
      end
    end
  end
end
