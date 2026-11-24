# frozen_string_literal: true

module EE
  module LabelNote # rubocop:disable Gitlab/BoundedContexts -- EE module for existing file
    extend ::Gitlab::Utils::Override

    override :label_url_method
    def label_url_method
      return :group_epics_url if noteable.is_a?(Epic)

      super
    end
  end
end
