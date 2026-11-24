# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      module SelfHosted
        class CodeSuggestionsLicenseProbe < BaseProbe
          extend ::Gitlab::Utils::Override

          validate :check_user_exists
          validate :validate_code_suggestions_availability

          after_validation :collect_instance_details, :collect_license_details

          def initialize(user)
            @user = user
          end

          private

          attr_reader :user

          def check_user_exists
            errors.add(:base, 'User not provided.') unless user
          end

          override :success_message
          def success_message
            _('License includes access to Code Suggestions.')
          end

          def validate_code_suggestions_availability
            return unless user
            return if Ability.allowed?(user, :access_code_suggestions)

            if ::License.feature_available?(:code_suggestions)
              text = _(
                'License includes access to Code Suggestions, but you lack the necessary ' \
                  'permissions to use this feature.'
              )

              errors.add(:base, text)

              return
            end

            errors.add(:base, _('License does not provide access to Code Suggestions.'))
          end

          def collect_instance_details
            details.add(:instance_id, Gitlab::GlobalAnonymousId.instance_id)
            details.add(:gitlab_version, Gitlab::VERSION)
          end

          def collect_license_details
            return unless license

            details.add(:license, license.license.as_json)
          end

          def license
            @license ||= License.current
          end
        end
      end
    end
  end
end
