# frozen_string_literal: true

module EE
  module BulkImports # rubocop:disable Gitlab/BoundedContexts -- existing non-EE module is not bounded
    module ProcessService
      extend ::Gitlab::Utils::Override

      private

      override :skip_pipeline?
      def skip_pipeline?(pipeline, _entity)
        return true if pipeline[:pipeline] == ::BulkImports::Projects::Pipelines::VulnerabilitiesPipeline &&
          ::Feature.disabled?(:import_vulnerabilities, bulk_import.user)

        super
      end
    end
  end
end
