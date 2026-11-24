# frozen_string_literal: true

module Ai
  module ActiveContext
    class Connection < ApplicationRecord
      self.table_name = :ai_active_context_connections

      ADVANCED_SEARCH_ADAPTERS = {
        elasticsearch: ::ActiveContext::Databases::Elasticsearch::Adapter,
        opensearch: ::ActiveContext::Databases::Opensearch::Adapter
      }.freeze

      ALL_ADAPTERS = ADVANCED_SEARCH_ADAPTERS.merge(
        postgresql: ::ActiveContext::Databases::Postgresql::Adapter
      ).freeze

      ELASTICSEARCH_COMPATIBLE_ADAPTERS = ADVANCED_SEARCH_ADAPTERS
      MASKED_PASSWORD = '*****'

      has_many :collections, class_name: 'Ai::ActiveContext::Collection'

      encrypts :options

      has_many :migrations, class_name: 'Ai::ActiveContext::Migration'
      has_many :tasks, class_name: 'Ai::ActiveContext::Task'
      has_many :enabled_namespaces, class_name: 'Ai::ActiveContext::Code::EnabledNamespace',
        inverse_of: :active_context_connection
      has_many :repositories, class_name: 'Ai::ActiveContext::Code::Repository', inverse_of: :active_context_connection

      validates :name, presence: true, length: { maximum: 255 }, uniqueness: true
      validates :adapter_class, presence: true, length: { maximum: 255 }
      validates :prefix, length: { maximum: 255 }, allow_nil: true
      validates :active, inclusion: { in: [true, false] }
      validates :options, presence: true
      validates_uniqueness_of :active, conditions: -> { where(active: true) }, if: :active

      validate :url_required_for_connection, if: :options_changed?, unless: :use_advanced_search_config?
      validate :check_elasticsearch_url_scheme, if: :options_changed?, unless: :use_advanced_search_config?
      validate :host_required_for_postgresql_connection, if: :options_changed?, unless: :use_advanced_search_config?

      after_destroy :reload_adapter
      after_save :reload_adapter
      after_commit :process_deactivation_async, on: :update, if: :saved_change_to_active?

      def self.active
        where(active: true).first
      end

      # Find connection by id. Defaults to active connection.
      def self.find_connection(id = nil)
        if id
          find_by(id: id)
        else
          active
        end
      end

      # Activates this connection and deactivates the previously active connection.
      # Note: deactivate! is destructive - it drops all associated and indexed data
      def activate!
        return if active?

        self.class.transaction do
          self.class.active&.deactivate!
          update!(active: true)
        end
      end

      # Deactivates the connection by marking as inactive.
      # This enqueues an async worker that will:
      # 1. Drop collections from the external service (Elasticsearch/OpenSearch)
      # 2. Delete the connection record (which triggers loose FK async cleanup of repositories)
      # Associated repositories are cleaned up asynchronously via loose foreign key.
      def deactivate!
        return unless active?

        update!(active: false)
      end

      def options
        opts = if use_advanced_search_config?
                 ::Gitlab::CurrentSettings.elasticsearch_config
               elsif elasticsearch_compatible_adapter?
                 super.merge('url' => elasticsearch_url_with_credentials)
               else
                 super
               end

        # The prefix enables connection-specific index isolation for different environments
        opts[:prefix] = prefix if prefix.present?
        opts
      end

      def use_advanced_search_config?
        advanced_search_adapter? && use_advanced_search_config_option == true
      end

      def use_advanced_search_config_option
        read_attribute(:options)['use_advanced_search_config']
      end

      def adapter_name
        ALL_ADAPTERS.key(adapter_class&.safe_constantize)&.to_s
      end

      def stored_options
        read_attribute(:options).to_h
      end

      def masked_stored_options
        stored_options.merge(
          'password' => stored_options['password'].present? ? MASKED_PASSWORD : nil,
          'aws_secret_access_key' => stored_options['aws_secret_access_key'].present? ? MASKED_PASSWORD : nil
        ).compact
      end

      def update_options!(new_options)
        filtered = new_options.reject { |_, v| v == MASKED_PASSWORD }
        update!(options: stored_options.merge(filtered))
      end

      def adapter
        ::ActiveContext::Adapter.for_connection(self)
      end

      def reload_adapter
        ::ActiveContext::Adapter.reset
      end

      private

      def process_deactivation_async
        return if active?

        ::Ai::ActiveContext::ConnectionCleanupWorker.perform_async(id)
      end

      def url_required_for_connection
        return unless elasticsearch_compatible_adapter?
        return if read_attribute(:options)['url'].present?

        errors.add(:base, "URL can't be blank")
      end

      def check_elasticsearch_url_scheme
        return unless elasticsearch_compatible_adapter?

        ::EE::Search::ElasticsearchUrl.validate!(elasticsearch_url)
      rescue ::Gitlab::HTTP_V2::UrlBlocker::BlockedUrlError
        errors.add(:base, "only supports valid HTTP(S) URLs")
      end

      def elasticsearch_url
        ::EE::Search::ElasticsearchUrl.parse(read_attribute(:options)['url'].to_s)
      end

      def elasticsearch_url_with_credentials
        ::EE::Search::ElasticsearchUrl.with_credentials(
          read_attribute(:options)['url'].to_s,
          username: read_attribute(:options)['username'],
          password: read_attribute(:options)['password']
        )
      end

      def host_required_for_postgresql_connection
        return unless postgresql_adapter?
        return if read_attribute(:options)['host'].present?

        errors.add(:base, "host can't be blank")
      end

      def advanced_search_adapter?
        ADVANCED_SEARCH_ADAPTERS.value?(adapter_class&.safe_constantize)
      end

      def postgresql_adapter?
        adapter_class&.safe_constantize == ::ActiveContext::Databases::Postgresql::Adapter
      end

      def elasticsearch_compatible_adapter?
        ELASTICSEARCH_COMPATIBLE_ADAPTERS.value?(adapter_class&.safe_constantize)
      end
    end
  end
end
