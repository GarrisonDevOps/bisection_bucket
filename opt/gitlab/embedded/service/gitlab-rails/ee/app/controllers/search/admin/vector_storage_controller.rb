# frozen_string_literal: true

module Search
  module Admin
    class VectorStorageController < ::Admin::ApplicationController
      include Gitlab::Utils::StrongMemoize

      feature_category :global_search
      urgency :low

      before_action :set_vector_storage,
        only: [:show, :connect_custom_elasticsearch_vector_storage, :connect_custom_opensearch_vector_storage,
          :connect_custom_postgresql_vector_storage]

      def show; end

      def use_advanced_search_cluster_for_semantic_search
        ::Ai::ActiveContext::ConnectionService.connect_to_advanced_search_cluster

        flash[:notice] = s_('SemanticSearch|Successfully connected. Indexing will start soon.')

        redirect_to redirect_path(anchor: 'js-semantic-search-settings')
      rescue ::Ai::ActiveContext::ConnectionService::ConnectionError => e
        flash[:alert] = format(s_('SemanticSearch|Failed to connect: %{error}.'), error: e.message)

        redirect_to search_vector_storage_admin_application_settings_path
      end

      def connect_custom_elasticsearch_vector_storage
        with_connection_response do
          ::Ai::ActiveContext::ConnectionService.connect_to_custom_elasticsearch_cluster(elasticsearch_params)
        end
      end

      def connect_custom_opensearch_vector_storage
        with_connection_response do
          ::Ai::ActiveContext::ConnectionService.connect_to_custom_opensearch_cluster(opensearch_params)
        end
      end

      def connect_custom_postgresql_vector_storage
        with_connection_response do
          ::Ai::ActiveContext::ConnectionService.connect_to_custom_postgresql_cluster(postgresql_params)
        end
      end

      def disable_semantic_search
        ::Ai::ActiveContext::ConnectionService.disable_connection

        flash[:notice] = s_('SemanticSearch|Semantic search will be disabled soon.')

        redirect_to redirect_path(anchor: 'js-semantic-search-settings')
      end

      private

      def with_connection_response
        yield

        flash[:notice] = s_('SemanticSearch|Successfully connected. Indexing will start soon.')

        redirect_to redirect_path(anchor: 'js-semantic-search-settings')
      rescue ::Ai::ActiveContext::ConnectionService::ConnectionError => e
        flash.now[:alert] = format(s_('SemanticSearch|Failed to connect: %{error}.'), error: e.message)
        render :show
      rescue ActiveRecord::RecordInvalid => e
        flash.now[:alert] =
          format(s_('SemanticSearch|Failed to connect: %{error}.'), error: e.record.errors.full_messages.to_sentence)
        render :show
      end

      def redirect_path(anchor: 'js-semantic-search-settings')
        search_admin_application_settings_path(anchor: anchor)
      end

      def set_vector_storage
        existing_adapter = connection&.adapter_name
        selected_adapter = submitted_adapter_name || existing_adapter

        @presenter = ::Search::Admin::VectorStoragePresenter.new(
          using_advanced_search: use_advanced_search_config,
          custom_active: connection.present? && !use_advanced_search_config,
          inputs_disabled: use_advanced_search_config,
          selected_adapter_name: selected_adapter,
          existing_adapter_name: existing_adapter,
          adapter_configs: build_adapter_configs(existing_adapter)
        )
      end

      def build_adapter_configs(existing_adapter)
        ::Ai::ActiveContext::Connection::ALL_ADAPTERS.keys.to_h do |adapter|
          adapter_name = adapter.to_s
          options = options_for_adapter(adapter_name, existing_adapter)

          [adapter_name, {
            'options' => options.except('password', 'aws_secret_access_key'),
            'password_value' => options['password'].presence,
            'aws_secret_value' => options['aws_secret_access_key'].presence
          }]
        end
      end

      def options_for_adapter(adapter, existing_adapter_name)
        if submitted_adapter_name == adapter
          submitted_params.to_h
        elsif existing_adapter_name == adapter
          use_advanced_search_config ? {} : connection&.masked_stored_options || {}
        else
          {}
        end
      end

      def submitted_params
        case submitted_adapter_name
        when 'elasticsearch' then elasticsearch_params
        when 'opensearch' then opensearch_params
        when 'postgresql' then postgresql_params
        end
      end
      strong_memoize_attr :submitted_params

      def submitted_adapter_name
        adapter = params.permit(:adapter)[:adapter]
        adapter if ::Ai::ActiveContext::Connection::ALL_ADAPTERS.key?(adapter&.to_sym)
      end
      strong_memoize_attr :submitted_adapter_name

      def connection
        ::Ai::ActiveContext::Connection.active
      end
      strong_memoize_attr :connection

      def use_advanced_search_config
        connection&.use_advanced_search_config?
      end
      strong_memoize_attr :use_advanced_search_config

      def elasticsearch_params
        params.permit(:url, :username, :password)
      end
      strong_memoize_attr :elasticsearch_params

      def opensearch_params
        params.permit(:url, :username, :password, :aws, :aws_region, :aws_access_key, :aws_secret_access_key,
          :aws_role_arn)
      end
      strong_memoize_attr :opensearch_params

      def postgresql_params
        params.permit(:host, :port, :database, :user, :password)
      end
      strong_memoize_attr :postgresql_params
    end
  end
end
