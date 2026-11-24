# frozen_string_literal: true

module RemoteDevelopment
  module DevfileOperations
    class YamlParser
      include Messages

      # @param [Hash] context
      # @return [Gitlab::Fp::Result]
      def self.parse(context)
        context => {
          devfile_yaml: String => devfile_yaml
        }

        begin
          devfile_hash = YAML.safe_load(devfile_yaml)

          unless devfile_hash.is_a?(Hash)

            return Gitlab::Fp::Result.err(DevfileYamlParseFailed.new(
              details: "Devfile YAML could not be parsed: " \
                "YAML parsing resulted in '#{devfile_yaml.class}' type instead of 'Hash'",
              context: context
            ))
          end
          # load YAML, convert YAML to JSON and load it again to remove YAML vulnerabilities
          devfile_to_json_and_back_to_yaml = YAML.safe_load(devfile_hash.to_json)
          # symbolize keys for domain logic processing of devfile (to_h is to avoid nil dereference error in RubyMine)
          devfile = devfile_to_json_and_back_to_yaml.to_h.deep_symbolize_keys

        rescue Psych::SyntaxError => e
          return Gitlab::Fp::Result.err(DevfileYamlParseFailed.new(
            details: "There is a syntax error in the devfile YAML: '#{e.message}'",
            context: context
          ))

        rescue JSON::GeneratorError => e
          return Gitlab::Fp::Result.err(DevfileYamlParseFailed.new(
            details: "Devfile YAML could not be converted to JSON" \
              ", which can indicate YAML security vulnerabilities: '#{e.message}'",
            context: context
          ))

        rescue StandardError => e
          return Gitlab::Fp::Result.err(DevfileYamlParseFailed.new(
            details: "There was an error parsing or loading the devfile YAML: '#{e.message}'",
            context: context
          ))
        end

        Gitlab::Fp::Result.ok(context.merge({
          devfile: devfile
        }))
      end
    end
  end
end
