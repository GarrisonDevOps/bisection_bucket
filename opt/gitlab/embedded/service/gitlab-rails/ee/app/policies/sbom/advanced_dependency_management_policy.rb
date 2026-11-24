# frozen_string_literal: true

module Sbom
  module AdvancedDependencyManagementPolicy
    extend ActiveSupport::Concern

    included do
      condition(:can_read_dependency_es_features, scope: :global) do
        advanced_dependency_management_allowed?
      end

      rule { ~can_read_dependency_es_features }.prevent :read_advanced_dependency_management

      private

      def advanced_dependency_management_allowed?
        ::Search::Elastic::SbomOccurrenceRefIndexHelper
          .advanced_dependency_management_allowed?
      end
    end
  end
end
