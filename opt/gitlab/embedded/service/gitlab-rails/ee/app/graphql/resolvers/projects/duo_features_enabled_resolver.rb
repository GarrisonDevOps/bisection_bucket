# frozen_string_literal: true

module Resolvers
  module Projects
    class DuoFeaturesEnabledResolver < BaseResolver
      type GraphQL::Types::Boolean, null: true

      alias_method :project, :object

      def resolve
        BatchLoader::GraphQL.for(project).batch do |projects, loader|
          ::Preloaders::Projects::CascadingSettingPreloader.new(projects, :duo_features_enabled).execute

          projects.each { |p| loader.call(p, p.duo_features_enabled) }
        end
      end
    end
  end
end
