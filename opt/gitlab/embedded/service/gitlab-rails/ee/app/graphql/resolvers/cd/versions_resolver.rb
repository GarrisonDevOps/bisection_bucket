# frozen_string_literal: true

module Resolvers
  module Cd
    class VersionsResolver < BaseResolver
      type ::Types::Cd::VersionType.connection_type, null: true

      alias_method :artifact_source, :object

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        artifact_source.versions
      end
    end
  end
end
