# frozen_string_literal: true

module WorkItems
  module DescriptionTemplateDefaults
    DEFAULT_SETTINGS_TEMPLATE_NAME = 'Default (Project Settings)'
    DEFAULT_SETTINGS_TEMPLATE_CATEGORY = 'Project Templates'

    SettingsDefaultTemplate = Struct.new(:name, :content, :project_id, :category, keyword_init: true) do
      def initialize(
        *args,
        name: DEFAULT_SETTINGS_TEMPLATE_NAME,
        category: DEFAULT_SETTINGS_TEMPLATE_CATEGORY,
        **kwargs
      )
        super
      end
    end
  end
end
