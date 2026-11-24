# frozen_string_literal: true

module EE
  module Banzai
    module Filter
      module SanitizationFilter
        extend ::Gitlab::Utils::Override
        extend ActiveSupport::Concern

        class_methods do
          def remove_link_class?(node)
            return if node['class'] == ::Banzai::Filter::JiraPrivateImageLinkFilter::CSS_WITH_ATTACHMENT_ICON

            super(node)
          end
        end
      end
    end
  end
end
