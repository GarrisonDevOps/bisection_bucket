# frozen_string_literal: true

module RemoteDevelopment
  module Settings
    class GitlabConfigReader
      include Messages

      RELEVANT_SETTING_NAMES = %i[
        gitlab_kas_external_url
      ].freeze

      # @param [Hash] context
      # @return [Gitlab::Fp::Result]
      def self.read(context)
        err_result = nil

        context[:settings].each_key do |setting_name|
          next unless RELEVANT_SETTING_NAMES.include?(setting_name)

          gitlab_config_value =
            case setting_name
            in :gitlab_kas_external_url
              # noinspection RubyResolve -- RubyMine can't find the dynamic Gitlab.config methods
              Gitlab.config.gitlab_kas&.external_url
            end

          next if gitlab_config_value.nil?

          setting_type = context[:setting_types][setting_name]

          unless gitlab_config_value.is_a?(setting_type)
            # err_result will be set to a non-nil Gitlab::Fp::Result.err if type check fails
            err_result = ::Gitlab::Fp::Result.err(SettingsGitlabConfigReadFailed.new(
              details: "Gitlab.config.#{setting_name} type of '#{gitlab_config_value.class}' " \
                "did not match initialized Remote Development Settings type of '#{setting_type}'."
            ))

            break
          end

          # CurrentSettings entry of correct type found for declared default setting, use its value as override
          context[:settings][setting_name] = gitlab_config_value
        end

        return err_result if err_result

        ::Gitlab::Fp::Result.ok(context)
      end
    end
  end
end
