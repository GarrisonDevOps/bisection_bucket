# frozen_string_literal: true

# Search::Elastic::Dsl::Field
#
# Provides a domain-specific language (DSL) for declaring Elasticsearch
# indexable fields within model or schema classes.
#
# Features:
# - Flat fields:        field :title, type: :keyword
# - Nested fields:      field(:scanner, type: :object) { field :id, type: :keyword }
# - Computed fields:    field :hash, value: ->(r) { r.data_hash }
# - Default values:     field :status, default: 'active'
# - Conditional fields: field :foo, if: -> { Feature.enabled?(:foo_field) }
# - Versioned fields:   field :new_column, version: 2525
# - Enrichment fields:  field :project_name, enrich: ->(ids) { ... }
#
# Implementation details:
# - Each field definition becomes a Hash (see `build_node`).
# - All fields are stored in a class-level registry (`fields_registry`).
# - Nested fields are defined recursively within their parent's block.
# - Errors during DSL definition are tracked with Gitlab::ErrorTracking.
module Search
  module Elastic
    module Dsl
      module Field
        extend ActiveSupport::Concern

        included do
          # Registry for all declared fields for this class
          class_attribute :fields_registry, instance_accessor: false, default: {}
        end

        class_methods do
          # Declare a field and merge it into the class registry
          def field(name, **opts, &block)
            node = build_node(name, **opts, &block)

            # Merge immutably into class-level registry
            self.fields_registry = fields_registry.merge(name.to_sym => node)
          end

          private

          # Build a field node hash
          def build_node(name, **opts, &block)
            {
              name: name,
              type: opts[:type],
              enrich: opts[:enrich],
              value: opts[:value],
              default: opts[:default],
              version: opts[:version],
              condition: opts[:if],
              children: block ? build_nested(&block) : nil
            }
          end

          # Build nested fields using a temporary DSL context
          def build_nested(&block)
            context = NestedFieldContext.new(self)
            context.instance_eval(&block)
            context.nested_fields
          end
        end

        # NestedFieldContext
        #
        # DSL context for nested fields
        class NestedFieldContext
          attr_reader :nested_fields

          def initialize(builder)
            @builder = builder
            @nested_fields = {}
          end

          # Define nested field
          def field(name, **opts, &block)
            node = @builder.class_exec(name, opts, block) do |n, o, blk|
              build_node(n, **o, &blk)
            end

            @nested_fields[name.to_sym] = node
          end
        end
      end
    end
  end
end
