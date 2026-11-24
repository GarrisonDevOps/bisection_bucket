# frozen_string_literal: true

module EE
  module Users
    module BannedUser
      extend ActiveSupport::Concern

      prepended do
        after_commit :reindex_associations, on: [:create, :destroy]
      end

      private

      def reindex_associations
        # Not gated on the `hidden` migrations: their cached, fail-closed check could skip a
        # ban's reindex for good, and the writers omit the field until its mapping exists.
        ElasticAssociationIndexerWorker.perform_async(
          user.class.name, user.id, %i[issues merge_requests notes snippets]
        )
      end
    end
  end
end
