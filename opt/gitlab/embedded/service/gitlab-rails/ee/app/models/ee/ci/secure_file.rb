# frozen_string_literal: true

module EE
  # CI::SecureFile EE mixin
  #
  # This module is intended to encapsulate EE-specific model logic
  # and be prepended in the `Ci::SecureFile` model
  module Ci
    module SecureFile
      extend ActiveSupport::Concern

      EE_SEARCHABLE_ATTRIBUTES = %i[name].freeze

      prepended do
        include ::Geo::ReplicableModel
        include ::Geo::VerifiableModel
        include ::Geo::ReplicableCiArtifactable
        include ::Gitlab::SQL::Pattern

        delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :ci_secure_file_state)

        with_replicator ::Geo::CiSecureFileReplicator

        has_one :ci_secure_file_state, autosave: false, inverse_of: :ci_secure_file,
          class_name: 'Geo::CiSecureFileState', foreign_key: :ci_secure_file_id

        def verification_state_object
          ci_secure_file_state
        end
      end

      class_methods do
        extend ::Gitlab::Utils::Override

        # Search for a list of ci_secure_files based on the query given in `query`.
        #
        # @param [String] query term that will search over secure_file :name attribute
        #
        # @return [ActiveRecord::Relation<Ci::SecureFile>] a collection of secure files
        def search(query)
          return all if query.empty?

          fuzzy_search(query, EE_SEARCHABLE_ATTRIBUTES)
        end

        override :verification_state_table_class
        def verification_state_table_class
          ::Geo::CiSecureFileState
        end
      end

      def ci_secure_file_state
        super || build_ci_secure_file_state
      end
    end
  end
end
