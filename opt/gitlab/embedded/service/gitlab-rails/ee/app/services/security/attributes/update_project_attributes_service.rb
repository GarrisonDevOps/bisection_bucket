# frozen_string_literal: true

module Security
  module Attributes
    class UpdateProjectAttributesService < BaseService
      include Gitlab::Utils::StrongMemoize

      MAX_PROJECT_ATTRIBUTES = 20
      MAX_ATTRIBUTES = MAX_PROJECT_ATTRIBUTES * 2
      ATTACHED_AUDIT_EVENT_NAME = 'security_attribute_attached_to_project'
      DETACHED_AUDIT_EVENT_NAME = 'security_attribute_detached_from_project'

      def initialize(project:, current_user:, params:)
        @project = project
        @current_user = current_user
        @params = params
      end

      def execute
        return UnauthorizedError unless permitted?

        limits_errors = validate_limits
        return error_response('Too many attributes', errors: limits_errors) if limits_errors.present?

        validate_attributes
        return error_response('Invalid attributes', errors: validation_errors) if validation_errors.present?

        apply_changes
        create_audit_events

        ServiceResponse.success(payload: {
          project: project.reset,
          added_count: associations_to_create.size,
          removed_count: associations_to_destroy.size
        })
      rescue ActiveRecord::RecordInvalid
        error_response('Failed to update security attributes')
      end

      private

      attr_reader :project, :current_user, :params

      def validation_errors
        []
      end
      strong_memoize_attr :validation_errors

      def permitted?
        Ability.allowed?(current_user, :admin_security_attributes, project)
      end

      def root_namespace
        project.namespace.root_ancestor
      end
      strong_memoize_attr :root_namespace

      def add_attribute_ids
        raw_add_attribute_ids - common_attribute_ids
      end
      strong_memoize_attr :add_attribute_ids

      def remove_attribute_ids
        raw_remove_attribute_ids - common_attribute_ids
      end
      strong_memoize_attr :remove_attribute_ids

      # Attributes that appear in both add and remove lists should be excluded from both operations.
      # This prevents attempting to remove and re-add the same attribute, which would be redundant
      # and could cause issues in REPLACE mode where existing attributes might be incorrectly removed.
      def common_attribute_ids
        raw_add_attribute_ids & raw_remove_attribute_ids
      end
      strong_memoize_attr :common_attribute_ids

      def raw_add_attribute_ids
        params.dig(:attributes, :add_attribute_ids)&.map(&:to_i) || []
      end
      strong_memoize_attr :raw_add_attribute_ids

      def raw_remove_attribute_ids
        params.dig(:attributes, :remove_attribute_ids)&.map(&:to_i) || []
      end
      strong_memoize_attr :raw_remove_attribute_ids

      def associations_to_create
        (add_attribute_ids - existing_attributes.pluck_id).filter_map do |attribute_id|
          security_attribute = all_attributes_by_id[attribute_id]

          if security_attribute.blank?
            validation_errors << "Security attribute not found: #{attribute_id}"
            next
          end

          project.project_to_security_attributes.build(
            security_attribute: security_attribute,
            traversal_ids: project.namespace.traversal_ids,
            created_at: now,
            updated_at: now
          )
        end
      end
      strong_memoize_attr :associations_to_create

      def now
        Time.zone.now
      end
      strong_memoize_attr :now

      def associations_to_destroy
        project.project_to_security_attributes.by_attribute_id(remove_attribute_ids).to_a
      end
      strong_memoize_attr :associations_to_destroy

      def validate_limits
        errors = []
        errors << "Cannot process more than #{MAX_ATTRIBUTES} attributes at once" if exceeds_attribute_limit?
        errors << "Cannot exceed #{MAX_PROJECT_ATTRIBUTES} attributes per project" if exceeds_project_attribute_limit?
        errors
      end

      def exceeds_attribute_limit?
        add_attribute_ids.size + remove_attribute_ids.size > MAX_ATTRIBUTES
      end

      def exceeds_project_attribute_limit?
        expected_attribute_count > MAX_PROJECT_ATTRIBUTES
      end

      def expected_attribute_count
        current_count = existing_attributes.size
        attributes_to_add = associations_to_create.size
        attributes_to_remove = associations_to_destroy.size

        current_count + attributes_to_add - attributes_to_remove
      end

      def error_response(message, **payload)
        ServiceResponse.error(message: message, payload: { **payload })
      end

      def all_attributes_by_id
        (Security::Attribute.not_deleted.id_in(add_attribute_ids).include_category + existing_attributes).index_by(&:id)
      end
      strong_memoize_attr :all_attributes_by_id

      def existing_attributes
        project.security_attributes.not_deleted.include_category
      end
      strong_memoize_attr :existing_attributes

      def apply_changes
        Security::ProjectToSecurityAttribute.transaction do
          if associations_to_destroy.present?
            Security::ProjectToSecurityAttribute.id_in(associations_to_destroy.map(&:id)).delete_all
          end

          Security::ProjectToSecurityAttribute.bulk_insert!(associations_to_create, skip_duplicates: true)
        end

        publish_events
      end

      def publish_events
        events = associations_to_destroy.map do |assoc|
          Projects::SecurityAttributeChangedEvent.new(data: {
            project_id: project.id,
            security_attribute_id: assoc.security_attribute_id,
            event_type: Projects::SecurityAttributeChangedEvent::EVENT_TYPES[:removed]
          })
        end

        associations_to_create.each do |assoc|
          events << Projects::SecurityAttributeChangedEvent.new(data: {
            project_id: project.id,
            security_attribute_id: assoc.security_attribute_id,
            event_type: Projects::SecurityAttributeChangedEvent::EVENT_TYPES[:added]
          })
        end

        ::Gitlab::EventStore.publish_group(events) if events.any?
      end

      def validate_attributes
        associations_to_create.each do |project_to_security_attribute|
          validate_one_attribute_per_category(project_to_security_attribute.security_attribute)
        end
      end

      def existing_single_select_categories
        categories_being_removed = associations_to_destroy.map(&:security_attribute).filter_map do |attribute|
          attribute.security_category_id unless attribute.security_category.multiple_selection
        end.to_set

        existing_attributes.filter_map do |attribute|
          category_id = attribute.security_category_id unless attribute.security_category.multiple_selection
          category_id unless categories_being_removed.include?(category_id)
        end.to_set
      end
      strong_memoize_attr :existing_single_select_categories

      def validate_one_attribute_per_category(attribute)
        category = attribute.security_category
        return if category.multiple_selection

        category_id = category.id
        category_already_present = existing_single_select_categories.include?(category_id)
        existing_single_select_categories.add(category_id)
        return unless category_already_present

        validation_errors << "Cannot add multiple attributes from the same category #{category_id}"
      end

      def create_audit_events
        if associations_to_create.any?
          ::Gitlab::Audit::Auditor.audit(attached_audit_context) do
            associations_to_create.each do |association|
              event = build_attached_audit_event(association)
              ::Gitlab::Audit::EventQueue.push(event)
            end
          end
        end

        return if associations_to_destroy.none?

        ::Gitlab::Audit::Auditor.audit(detached_audit_context) do
          associations_to_destroy.each do |association|
            event = build_detached_audit_event(association)
            ::Gitlab::Audit::EventQueue.push(event)
          end
        end
      end

      def attached_audit_context
        {
          author: current_user,
          scope: project,
          target: project,
          name: ATTACHED_AUDIT_EVENT_NAME
        }
      end

      def detached_audit_context
        {
          author: current_user,
          scope: project,
          target: project,
          name: DETACHED_AUDIT_EVENT_NAME
        }
      end

      def build_attached_audit_event(association)
        attribute = association.security_attribute
        AuditEvents::BuildService.new(
          author: current_user,
          scope: project,
          target: attribute,
          created_at: now,
          message: "Attached security attribute #{attribute.name} to project #{project.name}",
          additional_details: {
            event_name: ATTACHED_AUDIT_EVENT_NAME,
            organization_id: project.organization_id,
            attribute_name: attribute.name,
            category_name: attribute.security_category.name,
            project_name: project.name,
            project_path: project.full_path
          }
        ).execute
      end

      def build_detached_audit_event(association)
        attribute = association.security_attribute
        AuditEvents::BuildService.new(
          author: current_user,
          scope: project,
          target: attribute,
          created_at: now,
          message: "Detached security attribute #{attribute.name} from project #{project.name}",
          additional_details: {
            event_name: DETACHED_AUDIT_EVENT_NAME,
            organization_id: project.organization_id,
            attribute_name: attribute.name,
            category_name: attribute.security_category.name,
            project_name: project.name,
            project_path: project.full_path
          }
        ).execute
      end
    end
  end
end
