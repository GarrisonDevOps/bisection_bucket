# frozen_string_literal: true

module RemoteDevelopment
  module Settings
    class NetworkPolicyEgressValidator
      include Messages

      # @param [Hash] context
      # @return [Gitlab::Fp::Result]
      def self.validate(context)
        unless context.fetch(:requested_setting_names).include?(:network_policy_egress)
          return Gitlab::Fp::Result.ok(context)
        end

        context => {
          settings: {
            network_policy_egress: Array => network_policy_egress,
          }
        }

        # NOTE: We deep_stringify_keys here because even though they will be strings in a real request,
        #       we use symbols during tests. JSON schema validators are the only place where keys need
        #       to be strings. All other internal logic uses symbols.
        network_policy_egress_stringified_keys = network_policy_egress.map(&:deep_stringify_keys)

        errors = validate_against_schema(network_policy_egress_stringified_keys)

        if errors.none?
          Gitlab::Fp::Result.ok(context)
        else
          Gitlab::Fp::Result.err(SettingsNetworkPolicyEgressValidationFailed.new(
            details: errors.join(". ")))
        end
      end

      # @param [Array] array_to_validate
      # @return [Array]
      def self.validate_against_schema(array_to_validate)
        schema = {
          "type" => "array",
          "items" => {
            "type" => "object",
            "required" => %w[
              allow
            ],
            "properties" => {
              "allow" => {
                "type" => "string"
              },
              "except" => {
                "type" => "array",
                "items" => {
                  "type" => "string"
                }
              }
            }
          }
        }

        schemer = JSONSchemer.schema(schema)
        errors = schemer.validate(array_to_validate)
        errors.map { |error| JSONSchemer::Errors.pretty(error) }
      end

      private_class_method :validate_against_schema
    end
  end
end
