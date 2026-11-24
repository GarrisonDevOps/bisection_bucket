# frozen_string_literal: true

module RequirementsManagement
  class ImportCsvService < ::Issuable::ImportCsv::BaseService
    def execute
      raise Gitlab::Access::AccessDeniedError unless Ability.allowed?(user, :create_requirement, project)

      super
    end

    private

    def create_object(attributes)
      super[:issue]
    end

    def create_object_class
      ::Issues::CreateService
    end

    def email_results_to_user
      Notify.import_requirements_csv_email(user.id, project.id, results).deliver_later
    end

    def attributes_for(row)
      super.merge(work_item_type: requirement_work_item_type)
    end

    def requirement_work_item_type
      ::WorkItems::TypesFramework::Provider.new(project).find_by_base_type(:requirement)
    end
    strong_memoize_attr :requirement_work_item_type
  end
end
