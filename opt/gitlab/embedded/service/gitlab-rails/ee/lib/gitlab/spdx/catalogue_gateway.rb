# frozen_string_literal: true

module Gitlab
  module SPDX
    class CatalogueGateway
      ONLINE_CATALOGUE_URL = 'https://spdx.org/licenses/licenses.json'
      OFFLINE_CATALOGUE_PATH = Rails.root.join('vendor/spdx.json').freeze

      def fetch
        catalogue
      end

      private

      def parse(json)
        build_catalogue(::Gitlab::Json.safe_parse(json, symbolize_names: true))
      end

      def catalogue
        parse(File.read(OFFLINE_CATALOGUE_PATH))
      end

      def build_catalogue(hash)
        ::Gitlab::SPDX::Catalogue.new(hash)
      end
    end
  end
end
