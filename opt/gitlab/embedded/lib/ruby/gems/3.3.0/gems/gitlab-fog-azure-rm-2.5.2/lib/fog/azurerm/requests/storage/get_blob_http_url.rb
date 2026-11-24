module Fog
  module AzureRM
    class Storage
      # This class provides the actual implemention for service calls.
      class Real
        # Get an expiring http blob url from Azure blob storage
        #
        # @param container_name [String] Name of container containing blob
        # @param blob_name [String] Name of blob to get expiring url for
        # @param expires [Time] An expiry time for this url
        #
        # @return [String] - http url for blob
        #
        # @see https://msdn.microsoft.com/en-us/library/azure/mt584140.aspx
        #
        def get_blob_http_url(container_name, blob_name, expires, options = {})
          relative_path = "#{container_name}/#{blob_name}"
          relative_path = remove_trailing_periods_from_path_segments(relative_path)
          params = {
            service: 'b',
            resource: 'b',
            permissions: 'r',
            expiry: expires.utc.iso8601,
            content_disposition: options[:content_disposition]
          }
          token = signature_client(expires).generate_service_sas_token(relative_path, params)
          uri = @blob_client.generate_uri(relative_path, {}, { encode: true })
          url = "#{uri}?#{token}"
          url.sub('https:', 'http:')
        end
      end

      # This class provides the mock implementation for unit tests.
      class Mock
        def get_blob_http_url(*)
          'http://mockaccount.blob.core.windows.net/test_container/test_blob?token'
        end
      end
    end
  end
end
