# frozen_string_literal: true

module Gitlab
  module Ingestion
    #
    # Provides a DSL to define bulk updatable ingestion tasks.
    #
    # Tasks including this module should set a configuration value
    # and implement the template method.
    #
    # Configuration value;
    #
    #   `model`: The ActiveRecord model which the task is ingesting the data for.
    #   `scope`: Additional filtering scope for the update query.
    #
    # Template method;
    #
    #   `attributes`:   Returns an array of Hash objects that contain the name of the attributes and their values
    #                   as key & value pairs.
    #
    module BulkUpdatableTask
      include Gitlab::Utils::StrongMemoize

      SQL_TEMPLATE = <<~SQL
        UPDATE
          %<table_name>s
        SET
          %<set_values>s
        FROM
          (%<values>s) AS map(%<map_schema>s)
        WHERE
          %<table_name>s.%<primary_key>s = map.%<primary_key>s
          %<scope>s
        RETURNING
          %<table_name>s.%<primary_key>s
      SQL

      def self.included(base)
        base.singleton_class.attr_accessor :model
        base.singleton_class.attr_accessor :scope
      end

      def execute
        return unless attribute_names.present?

        result_set = connection.execute(update_sql)

        after_update(result_set.values.flatten)
      end

      private

      delegate :model, to: :'self.class', private: true
      delegate :table_name, :primary_key, :column_for_attribute, :type_for_attribute, :connection,
        to: :model, private: true

      def update_sql
        format(
          SQL_TEMPLATE,
          table_name: table_name,
          set_values: set_values,
          values: values,
          primary_key: primary_key,
          map_schema: map_schema,
          scope: scope
        )
      end

      def set_values
        attribute_names.map do |attribute|
          "#{attribute} = map.#{attribute}::#{sql_type_for(attribute)}"
        end.join(', ')
      end

      def sql_type_for(attribute)
        col = column_for_attribute(attribute)

        col.sql_type_metadata.sql_type
      end

      # Important Note:
      #   Sorting the VALUES list by the primary key is important to prevent
      #   deadlock errors. The bulk UPDATE locks the matched rows in the order
      #   they appear in the VALUES list, so concurrent ingestion transactions
      #   (e.g. advisory-driven CVS scans and pipeline report ingestion) that
      #   touch the same rows must acquire those row locks in a consistent
      #   order. See gitlab-org/gitlab#606404.
      def values
        attributes.map { |attribute_map| build_values_for(attribute_map) }
                  .sort_by { |row| row[primary_key_index] }
                  .then { |serialized_attributes| Arel::Nodes::ValuesList.new(serialized_attributes) }
                  .to_sql
      end

      def primary_key_index
        attribute_names.index { |name| name.to_s == primary_key.to_s } ||
          raise(ArgumentError, "Primary key `#{primary_key}` not found in attribute_names: #{attribute_names.inspect}")
      end

      def build_values_for(attribute_map)
        attribute_map.map { |attribute, value| type_for_attribute(attribute).serialize(value) }
      end

      def map_schema
        attribute_names.join(', ')
      end

      def attribute_names
        strong_memoize(:attribute_names) do
          attributes.first&.keys
        end
      end

      def attributes
        raise "Implement the `attributes` template method!"
      end

      def after_update(updated_record_ids)
        # Template method
      end

      def scope
        return unless self.class.scope

        "AND #{self.class.scope}"
      end
    end
  end
end
