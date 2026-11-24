# frozen_string_literal: true

module EE
  module Gitlab
    module FakeApplicationSettings
      def elasticsearch_indexes_project?(_project)
        false
      end

      def elasticsearch_indexes_namespace?(_namespace)
        false
      end

      def elasticsearch_url
        read_attribute(:elasticsearch_url).split(',').map do |s|
          URI.parse(s.strip)
        end
      end

      def elasticsearch_config
        configured_timeout = if Rails.env.test?
                               ApplicationSetting::ELASTIC_REQUEST_TIMEOUT
                             else
                               elasticsearch_client_request_timeout
                             end

        client_request_timeout = if configured_timeout.to_i > 0
                                   configured_timeout
                                 else
                                   ApplicationSetting::ELASTIC_REQUEST_TIMEOUT
                                 end

        {
          url: elasticsearch_url,
          client_adapter: elasticsearch_client_adapter,
          max_bulk_size_bytes: elasticsearch_max_bulk_size_mb.megabytes,
          max_bulk_concurrency: elasticsearch_max_bulk_concurrency,
          client_request_timeout: client_request_timeout
        }.compact
      end
    end
  end
end
