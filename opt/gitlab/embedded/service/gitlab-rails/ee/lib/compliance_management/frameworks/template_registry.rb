# frozen_string_literal: true

module ComplianceManagement
  module Frameworks
    class TemplateRegistry
      TEMPLATES_PATH = Rails.root.join('ee/config/compliance_management/templates')

      Template = Struct.new(:id, :template_version, :name, :description, :color, :requirements, :json,
        keyword_init: true) do
        include ::GlobalID::Identification
      end

      class << self
        def all
          @all ||= load_templates
        end

        def find(id)
          all.find { |template| template.id == id }
        end

        def reset!
          @all = nil
        end

        private

        def load_templates
          Dir.glob(TEMPLATES_PATH.join('*.json')).filter_map do |file_path|
            parse_template(file_path)
          end
        end

        def parse_template(file_path)
          json = File.read(file_path)
          data = ::Gitlab::Json.safe_parse(json)
          id = File.basename(file_path, '.json')

          Template.new(
            id: id,
            template_version: data['version'],
            name: data['name'],
            description: data['description'],
            color: data['color'],
            requirements: data['requirements'],
            json: json
          )
        end
      end
    end
  end
end
