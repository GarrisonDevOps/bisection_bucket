# frozen_string_literal: true

module Analytics
  module Orbit
    class NamespaceEnrollment < ApplicationRecord
      self.table_name = 'orbit_namespace_enrollments'

      belongs_to :namespace, inverse_of: :orbit_namespace_enrollment, optional: false

      enum :source, { direct: 0, beta: 1, trial: 2 }

      validate :namespace_is_top_level_group

      # Skips ended trials, so the cron does not turn Orbit off again after an admin turns it back on.
      scope :trials_not_ended_for, ->(enabled_namespaces) do
        trial.where(trial_ended_at: nil, namespace_id: enabled_namespaces.select(:root_namespace_id))
      end
      scope :preload_namespace, -> { preload(:namespace) }

      def self.record_beta(namespace_ids)
        record(namespace_ids, :beta)
      end

      def self.record_trial(namespace_ids)
        record(namespace_ids, :trial)
      end

      # record keeps an existing row, so a beta row is converted first. The conversion waits for a
      # concurrent beta cleanup that holds the row, and the insert then runs after that cleanup commits.
      def self.record_direct(namespace_ids)
        convert_beta_to_direct(namespace_ids)
        record(namespace_ids, :direct)
      end

      def self.convert_beta_to_direct(namespace_ids)
        beta.where(namespace_id: namespace_ids).update_all(source: sources[:direct], updated_at: Time.current)
      end

      def self.convert_beta_to_trial(namespace_ids)
        beta.where(namespace_id: namespace_ids).update_all(source: sources[:trial], updated_at: Time.current)
      end

      def self.beta_namespace_ids(namespace_ids)
        beta.where(namespace_id: namespace_ids).pluck_primary_key
      end

      # Locked rows make a concurrent beta-to-trial conversion wait and then find no beta row.
      def self.lock_beta_namespace_ids(namespace_ids)
        beta.where(namespace_id: namespace_ids).lock('FOR UPDATE').pluck_primary_key
      end

      def self.delete_for(namespace_ids)
        where(namespace_id: namespace_ids).delete_all
      end

      # insert_all skips validations, so only top-level group IDs go in.
      # A group that already has a row keeps it, so beta stays beta and trial stays trial.
      def self.record(namespace_ids, source)
        group_ids = ::Group.top_level.id_in(namespace_ids).pluck_primary_key
        return if group_ids.empty?

        insert_all(group_ids.map { |id| { namespace_id: id, source: sources[source] } }, unique_by: :namespace_id)
      end
      private_class_method :record

      private

      def namespace_is_top_level_group
        return if namespace.is_a?(::Group) && namespace.root?

        errors.add(:namespace, s_('Orbit|must be a top-level group'))
      end
    end
  end
end
