module Fog
  module AzureRM
    class Storage
      # This class provides the actual implemention for service calls.
      class Real
        # Generate a pre-signed URL for create an object in an Azure blob storage
        # This is to make this library compatible with CarrierWave.
        #
        # @param container_name [String] Name of container containing blob
        # @param blob_name [String] Name of blob to get expiring url for
        # @param expires [Time] An expiry time for this url
        #
        # @return [String] - https url for blob
        #
        # @see https://docs.microsoft.com/en-us/rest/api/storageservices/put-blob
        #
        def put_object_url(bucket_name, object_name, expire_at, _upload_options)
          put_blob_https_url(bucket_name, object_name, expire_at)
        end
      end

      # This class provides the mock implementation for unit tests.
      class Mock
        def put_object_url(*args)
          put_blob_https_url(*args)
        end
      end
    end
  end
end
