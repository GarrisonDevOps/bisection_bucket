# frozen_string_literal: true

module Search
  module Elastic
    module Filters
      module ExecutionFallback
        # Composer provides a lightweight DSL for defining fallback filters
        # that can be executed outside Elasticsearch.
        #
        # It allows enrichment classes to register:
        #
        #   - A filter argument key (e.g., :even_only_filter)
        #   - The instance method that computes values for a batch of record IDs
        #     (defaults to :perform_preload)
        #   - An optional normalization method for user-provided filter values
        #   - An optional `namespace:` override to control where the filter is registered
        #
        # When `fallback_filter` is declared:
        #
        #   1. A class-level execution method is defined that instantiates
        #      the enrichment with a collection of record IDs and invokes
        #      the configured instance method.
        #
        #   2. If a normalization method is provided (or already defined),
        #      a class-level `normalize_filter` method is exposed that
        #      delegates to the corresponding instance method.
        #
        #   3. The enrichment class registers in a frozen `ENRICHMENTS`
        #      constant for discovery by Executor.
        #
        #      By default, registration occurs under the class namespace
        #      (i.e., `module_parent`). If the class is defined at the
        #      top level, it registers under itself. A custom namespace
        #      can be provided explicitly via the `namespace:` option.
        #
        # Guarantees:
        #
        #   - Duplicate filter registration raises an error.
        #   - Undefined normalization methods raise an error.
        #   - Execution method existence is validated at call time.
        #   - ENRICHMENTS is immutable per namespace.
        #   - Registrations are isolated by namespace.
        #
        # This module is intended to be extended by enrichment classes:
        #
        #   module Vulnerability
        #     class FalsePositive
        #       extend Composer
        #
        #       def initialize(ids)
        #         @ids = ids
        #       end
        #
        #       def perform_preload
        #         ...
        #       end
        #
        #       private
        #
        #       def normalize_boolean(value)
        #         ...
        #       end
        #
        #       fallback_filter :false_positive,
        #                       normalize_with: :normalize_boolean
        #     end
        #   end
        #
        #   # Optional namespace override:
        #
        #   fallback_filter :false_positive,
        #                   namespace: Search::Elastic::Filters
        # How this framework works:
        #
        # - Strip fallback filters from the ES query
        # - Let ES apply all native filters
        # - Overfetch to preserve pagination density
        # - Apply fallback enrichment filtering on the ES result set
        # - Trim back to the requested window
        #
        # So the fallback logic effectively intersects with the ES-filtered dataset.
        # The only practical limitation (which is expected by design) is that this is post-filtering over a bounded ES
        # result window, so density depends on the over-fetch window and result cap. But within those constraints,
        # behavior is correct and pagination-safe.
        module Composer
          def fallback_filter(arg_key, method: :perform_preload, normalize_with: nil, namespace: module_parent)
            arg_key     = arg_key.to_sym
            method_name = (method || arg_key).to_sym

            validate_duplicate_registration!(arg_key)

            define_execution_method(arg_key, method_name)
            define_normalization_method(normalize_with)

            register_enrichment!(namespace)

            self
          end

          private

          def validate_duplicate_registration!(arg_key)
            return unless singleton_class.method_defined?(arg_key)

            raise ArgumentError, "Filter already registered: #{arg_key}"
          end

          def define_execution_method(arg_key, method_name)
            define_singleton_method(arg_key) do |ids|
              instance = new(ids)

              unless instance.respond_to?(method_name, true)
                raise ArgumentError, "Undefined instance method `#{method_name}` for #{self}"
              end

              instance.method(method_name).call
            end
          end

          def define_normalization_method(normalize_with)
            if normalize_with
              validate_normalization_method!(normalize_with)

              define_singleton_method(:normalize_filter) do |value|
                allocate.method(normalize_with).call(value)
              end

            elsif method_defined?(:normalize_filter) ||
                private_method_defined?(:normalize_filter)

              define_singleton_method(:normalize_filter) do |value|
                allocate.method(:normalize_filter).call(value)
              end
            end
          end

          def validate_normalization_method!(method_name)
            return if method_defined?(method_name) || private_method_defined?(method_name)

            raise ArgumentError, "Undefined instance method `#{method_name}` for #{self}"
          end

          # Registers under:
          #   - Parent module if present
          #   - Otherwise the class itself
          def register_enrichment!(namespace)
            owner = if namespace == Object
                      self
                    else
                      namespace
                    end

            enrichments =
              if owner.const_defined?(:ENRICHMENTS, false)
                owner.const_get(:ENRICHMENTS, false).dup
              else
                []
              end

            enrichments << self unless enrichments.include?(self)

            owner.const_set(:ENRICHMENTS, enrichments.freeze)
          end
        end
      end
    end
  end
end
