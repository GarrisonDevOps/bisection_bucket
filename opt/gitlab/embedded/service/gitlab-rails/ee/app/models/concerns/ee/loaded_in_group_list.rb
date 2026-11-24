# frozen_string_literal: true

module EE
  module LoadedInGroupList
    extend ActiveSupport::Concern

    class_methods do
      extend ::Gitlab::Utils::Override

      override :with_selects_for_list
      def with_selects_for_list
        super.preload(:saml_provider)
      end
    end
  end
end
