# frozen_string_literal: true

module EE
  module ContainerRegistry
    module Client
      include ::Gitlab::Utils::StrongMemoize

      Error = Class.new(StandardError)
      NotFoundError = Class.new(Error)

      # 100 pages of DEFAULT_TAGS_PAGE_SIZE is 1,000,000 tags; a guard against a never-ending Link chain.
      MAX_TAG_PAGES = 100

      def push_blob(name, digest, blob_io, size)
        response = HTTP
          .headers(base_headers.merge('Content-Length' => size))
          .put(get_upload_url(name, digest), body: blob_io)

        raise Error, "Push Blob error: #{response.body}" unless response.status.success?

        true
      end

      def push_manifest(name, tag, manifest, manifest_type)
        response = faraday.put("v2/#{name}/manifests/#{tag}", manifest, { 'Content-Type' => manifest_type })

        raise Error, "Push manifest error: #{response.body}" unless response.success?

        true
      end

      def blob_exists?(name, digest)
        faraday.head("/v2/#{name}/blobs/#{digest}").success?
      end

      def manifest_exists?(name, reference)
        faraday.head("/v2/#{name}/manifests/#{reference}").success?
      end

      # Pulls a blob from the Registry.
      # We currently use Faraday 0.12 which does not support streaming download yet
      # Given that we aim to migrate to HTTP.rb client and that updating Faraday is potentially
      # dangerous, we use HTTP.rb here.
      #
      # @return [Array] Returns a Enumerator reader and the size of the object
      def pull_blob(name, digest)
        blob_url = "/v2/#{name}/blobs/#{digest}"

        response = HTTP
          .headers(base_headers)
          .get(::Gitlab::Utils.append_path(base_uri, blob_url))

        if response.status.redirect?
          response = HTTP.get(response['Location'])
        end

        unless response.status.success?
          raise Error, "Pull error for blob #{digest}:#{response.status.code} - #{response.body}"
        end

        [response.body, response.headers['Content-Length'].to_i]
      end

      def repository_raw_manifest(name, reference)
        response = faraday_raw.get("/v2/#{name}/manifests/#{reference}")

        unless response.success?
          raise NotFoundError, "Get raw manifest error: #{response.status} - #{response.body}" if response.status == 404

          raise Error, "Get raw manifest error: #{response.status} - #{response.body}"
        end

        response.body
      end

      # Lists every tag by following the registry's `Link: rel="next"` pagination. `last` comes from the
      # page itself because Gitlab::Utils::LinkHeaderParser ignores Link URIs over 500 characters.
      #
      # @param name [String] repository path
      # @return [Array<String>] all tag names; empty if the repository does not exist (404)
      # @raise [Error] on any other non-2xx or malformed response, or if more than MAX_TAG_PAGES pages are returned
      def repository_tag_names(name)
        tag_names = []
        last = nil

        MAX_TAG_PAGES.times do
          response = faraday.get("/v2/#{name}/tags/list") do |req|
            req.params['n'] = ::ContainerRegistry::Client::DEFAULT_TAGS_PAGE_SIZE
            req.params['last'] = last if last
          end

          # Only a 404 on the first page means the repository is gone; after that it falls through and raises.
          return [] if response.status == 404 && last.nil?

          raise Error, "List tags error: #{response.status} - #{response.body}" unless response.success?
          raise Error, "List tags error: unexpected response body for #{name}" unless response.body.is_a?(Hash)

          tags = response.body['tags']
          page = tags.nil? ? [] : tags

          unless page.is_a?(Array) && page.all?(String)
            raise Error, "List tags error: unexpected tags value for #{name}"
          end

          tag_names.concat(page)
          last = page.last

          return tag_names if response.headers['Link'].to_s.exclude?('rel="next"')

          raise Error, "List tags error: next page advertised after an empty page for #{name}" if last.nil?
        end

        raise Error, "List tags error: more than #{MAX_TAG_PAGES} pages of tags for #{name}"
      end

      private

      # Used to set HTTP.rb client
      def base_headers
        {
          'Authorization' => "bearer #{options[:token]}",
          'User-Agent' => "GitLab/#{::Gitlab::VERSION}"
        }
      end

      def get_upload_url(name, digest)
        response = faraday.post("/v2/#{name}/blobs/uploads/")

        raise Error, "Get upload URL error: #{response.body}" unless response.success?

        upload_url = URI(response.headers['location'])
        upload_url.query = "#{upload_url.query}&#{URI.encode_www_form(digest: digest)}"
        upload_url
      end

      # Raw connection: skips the default JSON response middleware so manifest
      # bodies come back as byte-exact strings, which is required for digest
      # preservation when re-pushing manifests to the secondary registry.
      def faraday_raw
        strong_memoize(:faraday_raw) do
          faraday_base do |conn|
            initialize_connection(conn, options) do |connection|
              connection.headers['Accept'] = ::ContainerRegistry::Client::ACCEPTED_TYPES
            end
          end
        end
      end
    end
  end
end
