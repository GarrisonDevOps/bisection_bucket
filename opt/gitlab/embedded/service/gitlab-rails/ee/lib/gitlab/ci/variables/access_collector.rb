# frozen_string_literal: true

module Gitlab
  module Ci
    module Variables
      # Groups resolved CI/CD variables by owner, which becomes the audit
      # event scope.
      class AccessCollector
        include Enumerable

        CONTEXT_KEY = :ci_variables_access_collector

        # Streamed details are truncated, so cap the payload.
        MAX_KEYS_PER_SCOPE = 100

        Access = Struct.new(:scope, :accessed_keys, :hidden_keys, :truncated, keyword_init: true) do
          def size
            accessed_keys.size + hidden_keys.size
          end

          def truncated?
            !!truncated
          end
        end

        def self.for(context)
          context[CONTEXT_KEY] ||= new
        end

        def self.recorded_in(context)
          context[CONTEXT_KEY]
        end

        def initialize
          @accesses = {}
        end

        def record(scope:, key:, hidden:)
          access = @accesses[scope] ||=
            Access.new(scope: scope, accessed_keys: Set.new, hidden_keys: Set.new, truncated: false)

          keys = hidden ? access.hidden_keys : access.accessed_keys

          # A single variable resolves more than once when `value` is selected
          # several times through aliases.
          return if keys.include?(key)

          # Only a dropped key counts as truncation, so that consumers can trust
          # the key list whenever the flag is unset.
          if access.size >= MAX_KEYS_PER_SCOPE
            access.truncated = true
            return
          end

          keys << key
        end

        def empty?
          @accesses.empty?
        end

        def each(&block)
          @accesses.each_value(&block)
        end
      end
    end
  end
end
