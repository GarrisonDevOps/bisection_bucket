# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      module SelfHosted
        class VendoredFeaturesProbe < BaseProbe
          extend ::Gitlab::Utils::Override

          validate :check_no_vendored_features

          private

          def check_no_vendored_features
            titles = ::Ai::FeatureSetting.select_allowed(::Ai::FeatureSetting.vendored).map(&:title).sort
            return if titles.empty?

            errors.add(:base, format(_(
              "GitLab-managed models are not available with an offline cloud license. " \
                "Assign a self-hosted model in Model selection to these features: %{features}."
            ), features: titles.join(', ')))
          end

          override :success_message
          def success_message
            _('No feature uses a GitLab-managed model.')
          end
        end
      end
    end
  end
end
