require File.expand_path('../../custom_fog_errors.rb', __FILE__)

module Fog
  module AzureRM
    module Utilities
      # General utilities mixin.
      module General # rubocop:disable Metrics/ModuleLength
        # Pick Resource Group name from Azure Resource Id(String)
        def get_resource_group_from_id(id)
          id.split('/')[4]
        end

        # Pick Virtual Network name from Subnet Resource Id(String)
        def get_virtual_network_from_id(subnet_id)
          subnet_id.split('/')[8]
        end

        # Pick Virtual Machine name from Virtual Machine Extension Id(String)
        def get_virtual_machine_from_id(vme_id)
          vme_id.split('/')[VM_NAME_POSITION]
        end

        # Extract Endpoint type from (String)
        def get_end_point_type(endpoint_type)
          endpoint_type.split('/')[2]
        end

        def get_record_set_from_id(id)
          id.split('/')[8]
        end

        def get_type_from_recordset_type(type)
          type.split('/')[2]
        end

        def get_hash_from_object(object)
          hash = {}
          object.instance_variables.each { |attr| hash[attr.to_s.delete('@')] = object.instance_variable_get(attr) }
          hash
        end

        # Extract Traffic Manager Profile Name from Endpoint id(String)
        def get_traffic_manager_profile_name_from_endpoint_id(endpoint_id)
          endpoint_id.split('/')[8]
        end

        # Pick Express Route Circuit name from Id(String)
        def get_circuit_name_from_id(circuit_id)
          circuit_id.split('/')[8]
        end

        def get_record_type(type)
          type.split('/').last
        end

        def raise_azure_exception(exception, _msg)
          raise Fog::AzureRM::CustomAzureCoreHttpError.new(exception) if exception.is_a?(Azure::Core::Http::HTTPError)
          raise exception
        end

        # Make sure if input_params(Hash) contains all keys present in required_params(Array)
        def validate_params(required_params, input_params)
          missing_params = required_params.select { |param| param unless input_params.key?(param) }
          raise(ArgumentError, "Missing Parameters: #{missing_params.join(', ')} required for this operation") if missing_params.any?
        end

        def get_resource_from_resource_id(resource_id, position)
          data = resource_id.split('/') unless resource_id.nil?

          raise 'Invalid Resource ID' if data.count < 9 && data.count != 5

          data[position]
        end

        def random_string(length)
          (0...length).map { ('a'..'z').to_a[rand(26)] }.join
        end

        def storage_endpoint_suffix(environment = ENVIRONMENT_AZURE_CLOUD)
          case environment
          when ENVIRONMENT_AZURE_CHINA_CLOUD
            '.core.chinacloudapi.cn'
          when ENVIRONMENT_AZURE_US_GOVERNMENT
            '.core.usgovcloudapi.net'
          when ENVIRONMENT_AZURE_GERMAN_CLOUD
            '.core.cloudapi.de'
          else
            '.core.windows.net'
          end
        end

        # Per https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-access-azure-active-directory,
        # all endpoints use the same resource URL.
        def storage_resource(_environment = ENVIRONMENT_AZURE_CLOUD)
          'https://storage.azure.com'
        end

        # https://learn.microsoft.com/en-us/entra/identity-platform/authentication-national-cloud#microsoft-entra-authentication-endpoints
        def authority_url(environment = ENVIRONMENT_AZURE_CLOUD)
          case environment
          when ENVIRONMENT_AZURE_CHINA_CLOUD
            'https://login.chinacloudapi.cn'
          when ENVIRONMENT_AZURE_US_GOVERNMENT
            'https://login.microsoftonline.us'
          # This region is deprecated:
          # https://learn.microsoft.com/en-us/entra/identity-platform/authentication-national-cloud#azure-germany-microsoft-cloud-deutschland
          when ENVIRONMENT_AZURE_GERMAN_CLOUD
            'https://login.microsoftonline.de'
          else
            'https://login.microsoftonline.com'
          end
        end

        def get_blob_endpoint(storage_account_name, enable_https = false, environment = ENVIRONMENT_AZURE_CLOUD)
          protocol = enable_https ? 'https' : 'http'
          "#{protocol}://#{storage_account_name}.blob#{storage_endpoint_suffix(environment)}"
        end

        def get_blob_endpoint_with_domain(storage_account_name, enable_https = false, domain = 'blob.core.windows.net')
          protocol = enable_https ? 'https' : 'http'
          "#{protocol}://#{storage_account_name}.#{domain}"
        end

        # Parse storage blob/container to a hash
        def parse_storage_object(object)
          data = {}
          if object.is_a? Hash
            object.each do |k, v|
              if k == 'properties'
                v.each do |j, l|
                  data[j] = l
                end
              else
                data[k] = v
              end
            end
          else
            object.instance_variables.each do |p|
              kname = p.to_s.delete('@')
              if kname == 'properties'
                properties = object.instance_variable_get(p)
                properties.each do |k, v|
                  data[k.to_s] = v
                end
              else
                data[kname] = object.instance_variable_get(p)
              end
            end
          end

          data['last_modified'] = Time.parse(data['last_modified'])
          data['etag'] = data['etag'].delete('"')
          data
        end

        def get_image_name(id)
          id.split('/').last
        end

        def get_subscription_id(id)
          id.split('/')[2]
        end

        def remove_trailing_periods_from_path_segments(path)
          path.split('/').map { |segment| segment.gsub(/\.*$/, '') }.join('/')
        end
      end
    end
  end
end
