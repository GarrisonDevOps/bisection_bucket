# frozen_string_literal: true

require 'google/cloud/compute/v1'

module GoogleCloud
  module Compute
    class Client < ::GoogleCloud::BaseClient
      include Gitlab::Utils::StrongMemoize
      extend ::Gitlab::Utils::Override

      COMPUTE_API_ENDPOINT = 'https://compute.googleapis.com'

      # Retrieves the list of region resources available to the specified project.
      #
      # It will call the REST version of https://cloud.google.com/compute/docs/reference/rest/v1/region/list.
      #
      #
      # +filter+ A filter expression that filters resources listed in the response.
      # +max_results+ The maximum number of results per page that should be returned. If the number of available results
      #               is larger than `maxResults`, Compute Engine returns a `nextPageToken` that can be used to get
      #               the next page of results in subsequent list requests. Acceptable values are `0` to `500`,
      #               inclusive. (Default: `500`)
      # +order_by+ Sorts list results by a certain order. By default, results are returned in alphanumerical order based
      #            on the resource name. You can also sort results in descending order based on the creation timestamp
      #            using `orderBy="creationTimestamp desc"`.
      #            Possible values for column: name, creationTimestamp.
      #            Possible values for direction: asc, desc.
      # +page_token+ The page token returned in a previous request to get the next page.
      #
      # All parameters are optional.
      #
      # Return an instance of +Google::Cloud::Compute::V1::RegionList+.
      #
      # Possible exceptions:
      #
      # +GoogleCloud::AuthenticationError+ if an error occurs during the authentication.
      # +GoogleCloud::ApiError+ if an error occurs when interacting with the
      # Google Cloud API.
      def regions(filter: nil, max_results: 500, order_by: nil, page_token: nil)
        request = ::Google::Cloud::Compute::V1::ListRegionsRequest.new(
          project: google_cloud_project_id,
          filter: filter,
          max_results: max_results,
          order_by: order_by,
          page_token: page_token)

        handling_errors do
          regions_client.list(request).response
        end
      end

      # Retrieves the list of zone resources available to the specified project.
      #
      # It will call the REST version of https://cloud.google.com/compute/docs/reference/rest/v1/zones/list.
      #
      #
      # +filter+ A filter expression that filters resources listed in the response.
      # +max_results+ The maximum number of results per page that should be returned. If the number of available results
      #               is larger than `maxResults`, Compute Engine returns a `nextPageToken` that can be used to get
      #               the next page of results in subsequent list requests. Acceptable values are `0` to `500`,
      #               inclusive. (Default: `500`)
      # +order_by+ Sorts list results by a certain order. By default, results are returned in alphanumerical order based
      #            on the resource name. You can also sort results in descending order based on the creation timestamp
      #            using `orderBy="creationTimestamp desc"`.
      #            Possible values for column: name, creationTimestamp.
      #            Possible values for direction: asc, desc.
      # +page_token+ The page token returned in a previous request to get the next page.
      #
      # All parameters are optional.
      #
      # Return an instance of +Google::Cloud::Compute::V1::ZoneList+.
      #
      # Possible exceptions:
      #
      # +GoogleCloud::AuthenticationError+ if an error occurs during the authentication.
      # +GoogleCloud::ApiError+ if an error occurs when interacting with the
      # Google Cloud API.
      def zones(filter: nil, max_results: 500, order_by: nil, page_token: nil)
        request = ::Google::Cloud::Compute::V1::ListZonesRequest.new(
          project: google_cloud_project_id,
          filter: filter,
          max_results: max_results,
          order_by: order_by,
          page_token: page_token)

        handling_errors do
          zones_client.list(request).response
        end
      end

      # Retrieves the list of machine type resources available to the specified project.
      #
      # It will call the REST version of https://cloud.google.com/compute/docs/reference/rest/v1/machineTypes/list
      #
      #
      # +zone+ The name of the zone for this request.
      # +filter+ A filter expression that filters resources listed in the response.
      # +max_results+ The maximum number of results per page that should be returned. If the number of available results
      #               is larger than `maxResults`, Compute Engine returns a `nextPageToken` that can be used to get
      #               the next page of results in subsequent list requests. Acceptable values are `0` to `500`,
      #               inclusive. (Default: `500`)
      # +order_by+ Sorts list results by a certain order. By default, results are returned in alphanumerical order based
      #            on the resource name. You can also sort results in descending order based on the creation timestamp
      #            using `orderBy="creationTimestamp desc"`.
      #            Possible values for column: name, creationTimestamp.
      #            Possible values for direction: asc, desc.
      # +page_token+ The page token returned in a previous request to get the next page.
      #
      # All parameters except `zone` are optional.
      #
      # Return an instance of +Google::Cloud::Compute::V1::MachineTypeList+.
      #
      # Possible exceptions:
      #
      # +GoogleCloud::AuthenticationError+ if an error occurs during the authentication.
      # +GoogleCloud::ApiError+ if an error occurs when interacting with the
      # Google Cloud API.
      def machine_types(zone:, filter: nil, max_results: 500, order_by: nil, page_token: nil)
        request = ::Google::Cloud::Compute::V1::ListMachineTypesRequest.new(
          project: google_cloud_project_id,
          zone: zone,
          filter: filter,
          max_results: max_results,
          order_by: order_by,
          page_token: page_token)

        handling_errors do
          machine_types_client.list(request).response
        end
      end

      private

      def machine_types_client
        client_for(::Google::Cloud::Compute::V1::MachineTypes::Rest::Client)
      end
      strong_memoize_attr :machine_types_client

      def regions_client
        client_for(::Google::Cloud::Compute::V1::Regions::Rest::Client)
      end
      strong_memoize_attr :regions_client

      def zones_client
        client_for(::Google::Cloud::Compute::V1::Zones::Rest::Client)
      end
      strong_memoize_attr :zones_client

      override :google_cloud_project_id
      def google_cloud_project_id
        params[:google_cloud_project_id] || super
      end

      def client_for(klass)
        klass.new do |config|
          config.endpoint = COMPUTE_API_ENDPOINT
          config.credentials = external_credentials
        end
      end

      def external_credentials
        json_key_io = StringIO.new(::Gitlab::Json.dump(credentials))
        ext_credentials = Google::Auth::ExternalAccount::Credentials.make_creds(
          json_key_io: json_key_io,
          scope: CLOUD_PLATFORM_SCOPE
        )
        ::Google::Cloud::Compute::V1::Instances::Credentials.new(ext_credentials)
      end
      strong_memoize_attr :external_credentials
    end
  end
end
