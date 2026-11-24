# frozen_string_literal: true

module CloudConnector
  module Config
    extend self
    include Gitlab::Utils::StrongMemoize

    def base_url
      Gitlab.config.cloud_connector.base_url
    end

    def host
      parsed_uri.host
    end

    def port
      parsed_uri.port
    end

    private

    def parsed_uri
      URI.parse(base_url)
    end
    strong_memoize_attr :parsed_uri
  end
end
