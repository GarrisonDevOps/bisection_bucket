# frozen_string_literal: true

module Ai
  module ActiveContext
    class ConnectionService
      ConnectionError = Class.new(StandardError)

      def self.connect_to_advanced_search_cluster
        elastic_helper = ::Search::Elastic::Helper.default

        adapter = if elastic_helper.matching_distribution?(:opensearch)
                    :opensearch
                  elsif elastic_helper.matching_distribution?(:elasticsearch)
                    :elasticsearch
                  else
                    raise ConnectionError, 'Connection invalid'
                  end

        options = { use_advanced_search_config: true }
        name = "#{adapter}_advanced_search"

        create_or_update_active_connection(adapter, options, name: name)
      end

      def self.disable_connection
        Ai::ActiveContext::DisableWorker.perform_in(1.minute)
      end

      def self.connect_to_custom_elasticsearch_cluster(params)
        connect_to_custom_cluster(:elasticsearch, params)
      end

      def self.connect_to_custom_opensearch_cluster(params)
        connect_to_custom_cluster(:opensearch, params)
      end

      def self.connect_to_custom_postgresql_cluster(params)
        connect_to_custom_cluster(:postgresql, params)
      end

      private_class_method def self.connect_to_custom_cluster(adapter, params)
        options = params.to_h.stringify_keys
        options['aws'] = Gitlab::Utils.to_boolean(options['aws']) if options.key?('aws')
        options = options.compact

        create_or_update_active_connection(adapter, options, name: "#{adapter}_custom")
      end

      private_class_method def self.create_or_update_active_connection(adapter, options, name:)
        adapter_class = Ai::ActiveContext::Connection::ALL_ADAPTERS[adapter]

        Ai::ActiveContext::Connection.transaction do
          existing_connection = Ai::ActiveContext::Connection.find_by_name(name)

          if existing_connection&.active?
            existing_connection.update_options!(options)
          elsif existing_connection
            # Editing an inactive connection: the user sees an empty form, so save only what they typed
            existing_connection.update!(options: options)
            existing_connection.activate!
          else
            Ai::ActiveContext::Connection.create!(
              name: name,
              adapter_class: adapter_class.to_s,
              options: options
            ).activate!
          end
        end
      end
    end
  end
end
