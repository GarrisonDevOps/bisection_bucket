# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Shared behaviour for the join tables that link a Duo Workflow run to a GitLab
    # artifact (merge request, work item, pipeline, note). Each join model carries a
    # `link_type` describing how the workflow relates to the artifact.
    #
    # Including models declare their artifact association with `links_workflow_to`,
    # which wires up the presence validation. A workflow can link to the same artifact
    # more than once only under a different `link_type`; that uniqueness is enforced by
    # a DB unique index on (workflow_id, <artifact>_id, link_type), not a model
    # validation. See `ensure_link`.
    module WorkflowLinkable
      extend ActiveSupport::Concern

      included do
        # The name of the artifact association (e.g. :work_item) and its foreign key
        # column (e.g. :work_item_id), so a generic service can build a link without
        # knowing the concrete join model.
        class_attribute :workflow_artifact_association, instance_accessor: false
        class_attribute :workflow_artifact_foreign_key, instance_accessor: false

        belongs_to :workflow, class_name: 'Ai::DuoWorkflows::Workflow'
        belongs_to :project, optional: true
        belongs_to :namespace, optional: true

        validates :workflow, presence: true
        validates :link_type, presence: true

        validate :project_xor_namespace_present

        scope :with_link_type, ->(link_type) { where(link_type: link_type) }
      end

      class_methods do
        def declarative_policy_class
          'Ai::DuoWorkflows::WorkflowLinkPolicy'
        end

        def links_workflow_to(name, **options)
          self.workflow_artifact_association = name
          self.workflow_artifact_foreign_key = options[:foreign_key] || :"#{name}_id"

          belongs_to(name, **options)

          validates name, presence: true
        end

        # Idempotently ensures a link exists between the workflow and artifact under the
        # given link_type, without creating a duplicate. Returns the validation errors,
        # which are empty on success, so callers don't need the persisted record.
        #
        # Race-safe regardless of caller context. The atomic `upsert` (INSERT ... ON
        # CONFLICT against the unique index) dedupes concurrent links: it never raises
        # on conflict, so it neither creates a duplicate nor poisons an enclosing
        # transaction. `valid?` runs the presence and project/namespace validations
        # before the write; uniqueness is left to the DB index.
        def ensure_link(workflow:, artifact:, link_type:, extra_attributes: {})
          foreign_key = workflow_artifact_foreign_key
          finder = { workflow: workflow, link_type: link_type, workflow_artifact_association => artifact }

          link = new(**finder, project_id: workflow.project_id, namespace_id: workflow.namespace_id)
          link.assign_attributes(extra_attributes)
          return link.errors unless link.valid?

          # Build the payload from the validated record so enum (link_type) and the
          # artifact foreign key are cast to their stored DB values, which `upsert`
          # does not do for raw inputs.
          columns = %w[workflow_id project_id namespace_id link_type] << foreign_key.to_s
          columns.concat(extra_attributes.keys.map(&:to_s))

          upsert(link.attributes.slice(*columns), unique_by: [:workflow_id, foreign_key, :link_type])

          link.errors
        end
      end

      private

      def project_xor_namespace_present
        return if project_id.present? != namespace_id.present?

        errors.add(:base, 'either project_id or namespace_id must be present')
      end
    end
  end
end
