# frozen_string_literal: true

module EE
  module Gitlab
    module Graphql
      module UxSliByOperationName
        extend ActiveSupport::Concern

        EE_OPERATION_UX_SLI_MAP = {
          'projectVulnerabilities' => :render_vulnerabilities,
          'groupVulnerabilities' => :render_vulnerabilities,
          'instanceVulnerabilities' => :render_vulnerabilities
        }.freeze

        class_methods do
          def operation_ux_sli_map
            super.merge(EE_OPERATION_UX_SLI_MAP)
          end
        end
      end
    end
  end
end
