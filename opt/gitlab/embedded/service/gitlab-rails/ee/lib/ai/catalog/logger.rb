# frozen_string_literal: true

module Ai
  module Catalog
    class Logger < ::Gitlab::JsonLogger
      LOGGABLE_ITEM_ATTRS = %w[id project_id item_type].freeze
      LOGGABLE_VERSION_ATTRS = %w[id schema_version version].freeze
      LOGGABLE_CONSUMER_ATTRS = %w[
        id project_id group_id pinned_version_prefix parent_item_consumer_id service_account_id
      ].freeze

      def self.file_name_noext
        'ai_catalog'
      end

      def context(**options)
        @klass = options[:klass] if options.key?(:klass)
        @consumer = options[:consumer] if options.key?(:consumer)
        @version = options[:version] if options.key?(:version)
        @item = options[:item] if options.key?(:item)

        self
      end

      def default_attributes
        attrs = {
          feature_category: :ai_catalog_curation,
          Labkit::Fields::CLASS_NAME => klass
        }

        @item ||= consumer&.item || version&.item
        @version ||= consumer.pinned_version if consumer

        attrs.merge(
          item_attrs,
          version_attrs,
          consumer_attrs
        )
      end

      %i[info error debug warn].each do |level|
        define_method(level) do |message:, **options|
          attrs = options.merge(message: message)

          super(attrs)
        end
      end

      private

      attr_reader :klass, :consumer, :item, :version

      def item_attrs
        return {} unless item

        attrs = item.attributes.slice(*LOGGABLE_ITEM_ATTRS)
        attrs.transform_keys { |key| :"item_#{key}" }
      end

      def version_attrs
        return {} unless version

        attrs = version.attributes.slice(*LOGGABLE_VERSION_ATTRS)
        attrs.transform_keys { |key| :"version_#{key}" }
      end

      def consumer_attrs
        return {} unless consumer

        attrs = consumer.attributes.slice(*LOGGABLE_CONSUMER_ATTRS)
        attrs.transform_keys { |key| :"consumer_#{key}" }
      end
    end
  end
end
