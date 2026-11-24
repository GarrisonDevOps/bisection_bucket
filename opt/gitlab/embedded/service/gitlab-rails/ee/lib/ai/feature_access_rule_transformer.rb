# frozen_string_literal: true

module Ai
  module FeatureAccessRuleTransformer
    def self.transform(feature_rules)
      feature_rules.map do |_, rules|
        through_namespace = rules.first.through_namespace
        through_namespace_data = if through_namespace
                                   {
                                     id: through_namespace.id,
                                     name: through_namespace.name,
                                     full_path: through_namespace.full_path
                                   }
                                 end

        {
          through_namespace: through_namespace_data,
          features: rules.map(&:accessible_entity)
        }
      end
    end
  end
end
