# frozen_string_literal: true

module Gitlab
  module Graphql
    module Loaders
      module Vulnerabilities
        class SeverityOverrideLoader < LazyRelationLoader
          self.model = ::Vulnerability
          self.association = :severity_overrides

          def relation
            base_relation.with_author
          end
        end
      end
    end
  end
end
