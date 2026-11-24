# frozen_string_literal: true

module Resolvers
  module Cd
    class VersionSetEntriesResolver < BaseResolver
      type ::Types::Cd::VersionSetEntryType.connection_type, null: true

      alias_method :version_set, :object

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        version_set.version_set_entries
      end
    end
  end
end
