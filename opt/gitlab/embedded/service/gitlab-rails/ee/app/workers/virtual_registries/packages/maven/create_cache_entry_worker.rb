# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      class CreateCacheEntryWorker
        include ApplicationWorker

        data_consistency :sticky

        queue_namespace :dependency_proxy_blob
        feature_category :virtual_registry
        urgency :low

        defer_on_database_health_signal :gitlab_main, [:virtual_registries_packages_maven_cache_remote_entries],
          5.minutes
        deduplicate :until_executed
        idempotent!

        SHA1_HEADERS = %w[x-checksum-sha1 x-goog-meta-checksum-sha1].freeze
        MD5_HEADERS = %w[x-checksum-md5 x-goog-meta-checksum-md5].freeze

        ResponseError = Class.new(StandardError)

        def perform(upstream_id, path)
          upstream = ::VirtualRegistries::Packages::Maven::Upstream.find_by_id(upstream_id)

          return unless upstream

          Tempfile.create('virtual_registries_packages_maven_file', binmode: true) do |temp_file|
            file, etag = download_file(upstream, path, temp_file)

            ::VirtualRegistries::Packages::Maven::Cache::Entries::CreateOrUpdateService.new(
              upstream: upstream,
              params: {
                path: path,
                file: file,
                etag: etag,
                content_type: file.content_type,
                skip_permission_check: true
              }
            ).execute
          end
        rescue ResponseError, *::Gitlab::HTTP::HTTP_ERRORS => e
          Gitlab::ErrorTracking.log_exception(e, upstream_id: upstream_id, path: path)
        end

        private

        def download_file(upstream, path, temp_file)
          url = upstream.url_for(path)

          sha1_digest = OpenSSL::Digest.new('SHA1')
          md5_digest = OpenSSL::Digest.new('MD5') unless Gitlab::FIPS.enabled?
          sha1 = nil
          md5 = nil
          headers_checked = false

          response = Gitlab::HTTP.get(url, stream_body: true, headers: upstream.headers(path)) do |fragment|
            raise ResponseError, "Received error status #{fragment.code}" unless succeeded_response?(fragment)

            temp_file.write(fragment)
            temp_file.flush

            unless headers_checked
              sha1 = extract_checksum_from_fragment(fragment, SHA1_HEADERS)
              md5 = extract_checksum_from_fragment(fragment, MD5_HEADERS) unless Gitlab::FIPS.enabled?
              headers_checked = true
            end

            sha1_digest.update(fragment) unless sha1
            md5_digest&.update(fragment) unless md5 || Gitlab::FIPS.enabled?
          end

          args = {
            content_type: response.headers['content-type'],
            sha1: sha1 || sha1_digest.hexdigest,
            md5: md5 || md5_digest&.hexdigest
          }.compact_blank

          temp_file.rewind

          file = UploadedFile.new(temp_file.path, **args)

          [file, response.headers['etag']]
        end

        def succeeded_response?(fragment)
          fragment.http_response.is_a?(Net::HTTPSuccess)
        end

        def extract_checksum_from_fragment(fragment, possible_keys)
          possible_keys.lazy.map { |key| fragment.http_response.header[key] }.find(&:itself) # rubocop:disable Gitlab/NoFindInWorkers -- Not find from ActiveRecord
        end
      end
    end
  end
end
