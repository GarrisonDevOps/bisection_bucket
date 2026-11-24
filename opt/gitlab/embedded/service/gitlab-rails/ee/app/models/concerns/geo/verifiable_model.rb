# frozen_string_literal: true

module Geo
  # This concern is included on Model classes (as opposed to Registry classes)
  # to manage their verification states. Note that this concern does not handle
  # how verification is performed; see `VerifiableReplicator`.
  #
  # It handles both cases where verification state is stored in a separate
  # table or when it is stored in the same table as the model.

  module VerifiableModel
    extend ActiveSupport::Concern
    include ::Geo::VerificationState

    included do
      # We need lazy loaded states when querying the model for the data management
      # endpoint `api/v4/admin/data_management/{model} to avoid N+1 queries
      scope :with_state_details, -> do
        return unless separate_verification_state_table?

        includes(active_record_state_association.name)
      end
      scope :checksummed, -> do
        return where.not(verification_checksum: nil) unless separate_verification_state_table?

        association = active_record_state_association.name
        joins(association).where.not(association => { verification_checksum: nil })
      end
      scope :not_checksummed, -> do
        return where(verification_checksum: nil) unless separate_verification_state_table?

        association = active_record_state_association.name
        joins(association).where(association => { verification_checksum: nil })
      end

      # When storing verification details in the same table as the model,
      # the scope `available_verifiables` returns only those records
      # that are eligible for verification, i.e. the same as the scope
      # `verifiables`.
      scope :available_verifiables, -> {
        return verifiables unless separate_verification_state_table?

        joins(active_record_state_association.name)
      }

      scope :with_verification_state, ->(state) {
        condition = verification_arel_table[:verification_state].eq(verification_state_value(state))
        return where(condition) unless separate_verification_state_table?

        joins(active_record_state_association.name).where(condition)
      }

      def save_verification_details
        return unless Gitlab::Geo.primary?
        return unless self.class.replicator_class.verification_enabled?
        return unless self.class.separate_verification_state_table?

        return unless in_verifiables?

        # During a transaction, `verification_state_object` could be built before
        # a value for `verification_state_model_key` exists. So we check for that
        # before saving the `verification_state_object`
        unless verification_state_object.persisted?
          verification_state_object[self.class.verification_state_model_key] = id
        end

        verification_state_object.save!
      end

      after_save :save_verification_details

      def in_verifiables?
        # This query could be simpler, but this way it always uses the best index: the primary key index.
        cte = Gitlab::SQL::CTE.new(:verifiables, self.class.primary_key_in(self))
        verifiables = self.class.with(cte.to_arel).from(cte.alias_to(self.class.arel_table)).verifiables

        verifiables.exists?
      end

      # Implement this method in the class that includes this concern to specify
      # a different ActiveRecord association name that stores the verification state
      # See module EE::MergeRequestDiff for example
      def verification_state_object
        raise NotImplementedError if self.class.separate_verification_state_table?

        self
      end
    end

    class_methods do
      include Delay

      def pluck_verification_details_ids_in_range(range)
        verification_state_table_class
          .where(verification_state_model_key => range)
          .pluck(verification_state_model_key)
      end

      def pluck_verifiable_ids_in_range(range)
        verifiables(range).pluck_primary_key
      end

      def create_verification_details_for(primary_keys)
        rows = primary_keys.map do |id|
          { verification_state_model_key => id }
        end

        verification_state_table_class.insert_all(rows)
      end

      def delete_verification_details_for(primary_keys)
        verification_state_table_class
          .where(verification_state_model_key => primary_keys)
          .delete_all
      end

      def active_record_state_association
        @active_record_state_association ||= reflect_on_all_associations(:has_one).detect do |association|
          association.klass == verification_state_table_class
        end
      end
    end
  end
end
