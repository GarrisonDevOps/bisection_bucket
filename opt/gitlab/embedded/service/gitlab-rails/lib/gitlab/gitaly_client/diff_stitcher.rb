# frozen_string_literal: true

module Gitlab
  module GitalyClient
    class DiffStitcher
      include Enumerable

      def initialize(rpc_response)
        @rpc_response = rpc_response
        @diff_count = 0
        @exhausted = false
        @held = nil
      end

      # Only meaningful inside an #each block: true when the stream held
      # exactly one patch.
      def single_file?
        @exhausted && @diff_count == 1
      end

      def each(&block)
        current_diff = nil

        @rpc_response.each do |diff_msg|
          if current_diff.nil?
            diff_params = diff_msg.to_h.slice(*GitalyClient::Diff::ATTRS)
            # gRPC uses frozen strings by default, and we need to have an unfrozen string as it
            # gets processed further down the line. So we unfreeze the first chunk of the patch
            # in case it's the only chunk we receive for this diff.
            diff_params[:patch] = diff_msg.raw_patch_data.dup

            current_diff = GitalyClient::Diff.new(diff_params)
          else
            current_diff.patch << diff_msg.raw_patch_data
          end

          next unless diff_msg.end_of_patch

          @diff_count += 1

          # Each patch is held until the next one arrives, so the consumer of the
          # first patch can tell a single-file diff from the head of a longer one.
          # The held patch lives on the instance so a consumer that stops early
          # does not lose a patch already read off the stream.
          yield_held(current_diff, &block)

          current_diff = nil
        end

        @exhausted = true
        yield_held(nil, &block)
      end

      private

      def yield_held(next_diff)
        held = @held
        @held = next_diff

        yield held if held
      end
    end
  end
end
