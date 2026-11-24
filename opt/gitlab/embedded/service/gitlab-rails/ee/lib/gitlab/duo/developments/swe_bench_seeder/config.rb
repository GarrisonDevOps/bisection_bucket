# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class SweBenchSeeder
        class Config
          # Allows for setting a different base URL for pulling issues from different source (i.e. GitLab)
          def self.source_base_url
            ENV['SOURCE_BASE_URL'] || 'https://github.com'
          end

          def self.seed_base_url
            ENV['SEED_BASE_URL'] || 'http://gdk.test:3000'
          end

          def self.langsmith_endpoint
            ENV['LANGCHAIN_ENDPOINT'] || 'https://api.smith.langchain.com'
          end

          def self.langsmith_api_key!(missing_message:)
            api_key = ENV['LANGCHAIN_API_KEY']
            return api_key if api_key.present?

            puts missing_message
            nil
          end

          def self.langsmith_request(method:, path:, api_key:, query: nil, body: nil)
            url = "#{langsmith_endpoint}#{path}"
            headers = {
              'x-api-key' => api_key,
              'Content-Type' => 'application/json'
            }

            case method.to_sym
            when :get
              Gitlab::HTTP.get(url, headers: headers, query: query)
            when :post
              Gitlab::HTTP.post(url, headers: headers, query: query, body: (body ? body.to_json : nil))
            when :delete
              Gitlab::HTTP.delete(url, headers: headers, query: query)
            else
              raise ArgumentError, "Unsupported HTTP method: #{method.inspect}"
            end
          end
        end
      end
    end
  end
end
