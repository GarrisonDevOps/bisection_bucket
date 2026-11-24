# frozen_string_literal: true

namespace :gitlab do
  namespace :spdx do
    desc 'GitLab | SPDX | Import copy of the catalogue to store it offline'
    task import: :environment do
      require 'net/http'
      require 'gitlab/json'

      spdx_url = ::Gitlab::SPDX::CatalogueGateway::ONLINE_CATALOGUE_URL
      resp = Gitlab::HTTP.get(URI.parse(spdx_url))

      raise 'Network failure' if resp.code != 200

      data = ::Gitlab::Json.safe_parse(resp.body)

      path = ::Gitlab::SPDX::CatalogueGateway::OFFLINE_CATALOGUE_PATH
      output = ::Gitlab::Json.pretty_generate(data)
      File.write(path, output, mode: 'w')

      puts "Local copy of SPDX catalogue is saved to #{path}"

      Rails.cache.delete(::Gitlab::SPDX::Catalogue::LATEST_ACTIVE_LICENSES_CACHE_KEY)

    rescue StandardError => e
      puts "Import of SPDX catalogue failed: #{e}"
    end
  end
end
