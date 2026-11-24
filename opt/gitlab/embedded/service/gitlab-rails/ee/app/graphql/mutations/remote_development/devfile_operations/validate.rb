# frozen_string_literal: true

module Mutations
  module RemoteDevelopment
    module DevfileOperations
      class Validate < BaseMutation
        graphql_name "DevfileValidate"

        argument :devfile_yaml,
          GraphQL::Types::String,
          required: true,
          description: "Input devfile."

        field :valid,
          GraphQL::Types::Boolean,
          description: "Status whether devfile is valid or not."

        # @param [String] devfile_yaml
        # @return [Hash]
        def resolve(devfile_yaml)
          unless License.feature_available?(:remote_development)
            raise_resource_not_available_error!("'remote_development' licensed feature is not available")
          end

          yaml_content = devfile_yaml.is_a?(Hash) ? devfile_yaml[:devfile_yaml] : devfile_yaml

          domain_main_class_args = {
            devfile_yaml: yaml_content,
            user: current_user
          }

          response = ::RemoteDevelopment::CommonService.execute(
            domain_main_class: ::RemoteDevelopment::DevfileOperations::Main,
            domain_main_class_args: domain_main_class_args
          )

          {
            valid: response.success?,
            errors: response.error? ? response.message.split(",  ") : []
          }
        end
      end
    end
  end
end
