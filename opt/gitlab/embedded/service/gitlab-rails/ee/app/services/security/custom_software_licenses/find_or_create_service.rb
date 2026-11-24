# frozen_string_literal: true

module Security
  module CustomSoftwareLicenses
    class FindOrCreateService < ::BaseProjectService
      def initialize(project:, params: {})
        super(project: project, params: params.with_indifferent_access)
      end

      def execute
        name = params[:name].strip
        custom_software_license = CustomSoftwareLicense.find_or_create_by!(name: name, project: project) # rubocop:disable CodeReuse/ActiveRecord -- TO DO

        ServiceResponse.success(payload: { custom_software_license: custom_software_license })
      end
    end
  end
end
