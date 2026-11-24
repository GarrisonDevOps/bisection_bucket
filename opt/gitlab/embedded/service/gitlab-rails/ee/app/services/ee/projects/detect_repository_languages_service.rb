# frozen_string_literal: true

module EE
  module Projects
    module DetectRepositoryLanguagesService
      def execute
        repository_languages = super
        project.maintain_elasticsearch_update if project.maintaining_elasticsearch?

        repository_languages
      end
    end
  end
end
