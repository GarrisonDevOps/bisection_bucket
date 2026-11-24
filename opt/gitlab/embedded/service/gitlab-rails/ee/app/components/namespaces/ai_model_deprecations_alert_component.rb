# frozen_string_literal: true

module Namespaces
  class AiModelDeprecationsAlertComponent < ViewComponent::Base
    include Gitlab::Utils::StrongMemoize

    def initialize(group: nil)
      @group = group
    end

    attr_reader :group

    def render?
      selected_deprecated_models.any?
    end

    private

    def model_selection_path
      if Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) && @group.present?
        group_settings_gitlab_duo_model_selection_index_path(@group)
      else
        admin_gitlab_duo_model_selection_index_path
      end
    end

    def selected_deprecated_models
      return [] unless parser

      feature_settings.filter_map { |feature_setting| deprecated_model_for(feature_setting) }.uniq
    end
    strong_memoize_attr :selected_deprecated_models

    def feature_settings
      if Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) && @group.present?
        ::Ai::ModelSelection::NamespaceFeatureSetting
          .for_namespace(@group.id)
          .non_default
      else
        ::Ai::ModelSelection::InstanceModelSelectionFeatureSetting
          .non_default
      end
    end

    def deprecated_model_for(feature_setting)
      ref = feature_setting.offered_model_ref

      deprecated_models_by_id[ref] || feature_deprecated_model(feature_setting, ref)
    end

    def feature_deprecated_model(feature_setting, ref)
      return unless parser

      model = parser.feature_deprecated_models(feature_setting.feature).find { |m| m['identifier'] == ref }
      return unless model

      model.merge('feature_title' => feature_setting.title)
    end

    def deprecated_models_by_id
      @deprecated_models_by_id ||= Array(deprecated_models).index_by { |model| model["identifier"] }
    end

    def deprecated_models
      @deprecated_models ||= parser&.deprecated_models || []
    end

    def parser
      return unless catalog.success?

      catalog.parser
    end
    strong_memoize_attr :parser

    def catalog
      ::Ai::ModelSelection::ModelDefinitions.fetch
    end
    strong_memoize_attr :catalog

    def deprecation_list_item_message(model)
      message = if model['feature_title'].present?
                  _(
                    '%{strong_start}%{model_name}%{strong_end} (deprecated for ' \
                      '%{strong_start}%{feature_title}%{strong_end} on ' \
                      '%{strong_start}%{deprecation_date}%{strong_end} - ' \
                      'Removal scheduled for: %{strong_start}%{removal_version}%{strong_end})'
                  )
                else
                  _(
                    '%{strong_start}%{model_name}%{strong_end} (deprecated on ' \
                      '%{strong_start}%{deprecation_date}%{strong_end} - ' \
                      'Removal scheduled for: %{strong_start}%{removal_version}%{strong_end})'
                  )
                end

      # rubocop:disable Style/FormatString -- SafeBuffer#% auto-escapes interpolated values and keeps html_safe;
      # format/sprintf would return a plain String and lose both.
      html_escape(message) % {
        model_name: model['name'],
        feature_title: model['feature_title'],
        deprecation_date: model.dig('deprecation', 'deprecation_date'),
        removal_version: model.dig('deprecation', 'removal_version'),
        strong_start: '<strong>'.html_safe,
        strong_end: '</strong>'.html_safe
      }
      # rubocop:enable Style/FormatString
    end
  end
end
