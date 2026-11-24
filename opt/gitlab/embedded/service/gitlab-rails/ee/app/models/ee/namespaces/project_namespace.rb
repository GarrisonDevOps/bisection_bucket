# frozen_string_literal: true

module EE
  module Namespaces
    module ProjectNamespace
      extend ::Gitlab::Utils::Override

      override :licensed_feature_available?
      def licensed_feature_available?(feature)
        # There are project-specific rules like `open_source_license_granted?`
        # so we need to delegate to the associated project
        project.licensed_feature_available?(feature)
      end

      override :checked_file_template_project
      def checked_file_template_project
        project
      end
    end
  end
end
