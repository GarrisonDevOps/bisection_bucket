# frozen_string_literal: true

module Resolvers
  module Ml
    class CandidatesResolver < Resolvers::BaseResolver
      include LooksAhead

      type ::Types::Ml::CandidateType.connection_type, null: true

      def resolve_with_lookahead
        apply_lookahead(object.candidates)
      end

      private

      def preloads
        {
          creator: :user,
          ci_job: { ci_build: [:user, :project] }
        }
      end
    end
  end
end
