# frozen_string_literal: true

module Security
  module SecretDetection
    module ValidityChecks
      # A request's tokens, grouped by type for the verifiers and mapped back by the caller's id.
      class RawTokenBatch
        Token = Struct.new(:id, :token_type, :raw_token, keyword_init: true)

        def initialize(tokens)
          @tokens = tokens.map { |token| Token.new(**token.to_h.symbolize_keys.slice(*Token.members)) }
        end

        # @return [Hash{String => Array<String>}] distinct raw values per token type
        def by_type
          tokens.group_by(&:token_type).transform_values { |group| group.map(&:raw_token).uniq }
        end

        # @param statuses [Hash{String => Hash{String => Hash}}] the verifiers' answers, by type then raw value.
        #   Every raw value from #by_type must have one; a missing answer is a verifier bug, not a token state.
        # @return [Array<Hash>] one entry per caller id, without the raw value
        def results(statuses)
          tokens.map do |token|
            { id: token.id, token_type: token.token_type }.merge(statuses.dig(token.token_type, token.raw_token))
          end
        end

        private

        attr_reader :tokens
      end
    end
  end
end
