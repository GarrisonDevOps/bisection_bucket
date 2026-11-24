# frozen_string_literal: true

module EE
  module Gitlab
    module ImportExport
      module Project
        module ObjectBuilder
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          CADENCE_NOT_FOUND = :cadence_not_found

          override :prepare_attributes
          def prepare_attributes
            attributes = super

            attributes.dup.tap do |atts|
              atts.delete('project') if iteration?
            end
          end

          override :where_clause_for_klass
          def where_clause_for_klass
            return attrs_to_arel(attributes.slice('iid', 'start_date', 'due_date')) if iteration?
            return attrs_to_arel(attributes.slice('iid')) if epic?

            super
          end

          override :find
          def find
            return if group_relation_without_group?
            return find_iteration if iteration?
            return find_cadence if cadence?
            return find_scanner if scanner?
            return find_identifier if identifier?

            super
          end

          # rubocop: disable CodeReuse/ActiveRecord
          # Only attempt to find existing iteration. Do not try to create it
          # since iterations require associated cadences which we cannot create here
          def find_iteration
            return unless attributes['iterations_cadence']

            klass
              .joins(:iterations_cadence)
              .where(iterations_cadence: { title: attributes['iterations_cadence'].title })
              .find_by(where_clause)
          end

          # Cadences need scheduling attributes that are not exported, so only match existing ones.
          # A miss is cached as a truthy sentinel because find_with_cache uses ||=.
          def find_cadence
            cadence = find_with_cache { find_object || CADENCE_NOT_FOUND }
            cadence unless cadence == CADENCE_NOT_FOUND
          end

          def find_scanner
            Vulnerabilities::Scanner.find_or_create_by(attributes)
          end

          def find_identifier
            Vulnerabilities::Identifier.find_or_create_by(attributes)
          end
          # rubocop: enable CodeReuse/ActiveRecord

          private

          def iteration?
            klass == Iteration
          end

          def cadence?
            klass == Iterations::Cadence
          end

          def scanner?
            klass == Vulnerabilities::Scanner
          end

          def identifier?
            klass == Vulnerabilities::Identifier
          end

          override :group_level_object?
          def group_level_object?
            super || iteration? || cadence?
          end
        end
      end
    end
  end
end
