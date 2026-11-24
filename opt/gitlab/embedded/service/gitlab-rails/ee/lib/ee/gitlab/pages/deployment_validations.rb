# frozen_string_literal: true

module EE
  module Gitlab
    module Pages
      module DeploymentValidations
        extend ::Gitlab::Utils::Override
        extend ActiveSupport::Concern
        include ::Gitlab::Utils::StrongMemoize

        prepended do
          with_options unless: -> { errors.any? } do
            validate :validate_versioned_deployments_limit
            validate :validate_multiple_deployments_enabled
          end
        end

        override :max_size_from_settings
        def max_size_from_settings
          return super unless License.feature_available?(:pages_size_limit)

          project.closest_setting(:max_pages_size).megabytes
        end

        def validate_versioned_deployments_limit
          return if path_prefix.blank?
          return if project.pages_parallel_deployments_limit > project.pages_domain_level_parallel_deployments_count

          docs_link = Rails.application.routes.url_helpers.help_page_url(
            'user/project/pages/parallel_deployments.md',
            anchor: 'limits'
          )

          errors.add(:base, format(
            _("Namespace reached its allowed limit of %{limit} extra deployments. Learn more: %{docs_link}"),
            limit: project.pages_parallel_deployments_limit,
            docs_link: docs_link
          ))
        end

        def validate_multiple_deployments_enabled
          return if path_prefix.blank?
          return if ::Gitlab::Pages.multiple_versions_enabled_for?(project)

          errors.add(:base, _(
            "To configure a path_prefix, please add a license to your project."
          ))
        end
      end
    end
  end
end
