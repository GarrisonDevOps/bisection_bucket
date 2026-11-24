# frozen_string_literal: true

namespace :compliance_management do
  namespace :control_schema do
    desc 'Generate compliance requirements control expression JSON schema and control definitions'
    task generate: :environment do
      require 'json'

      schema_path = Rails.root.join('ee/app/validators/json_schemas/compliance_requirements_control_expression.json')
      controls_path = Rails.root.join('ee/config/compliance_management/requirement_controls.json')

      schema = ComplianceManagement::ComplianceFramework::Controls::Registry.generate_schema
      schema_json = ::Gitlab::Json.pretty_generate(schema) << "\n"
      File.write(schema_path, schema_json)
      puts "Generated schema at #{schema_path}"

      control_definitions = ComplianceManagement::ComplianceFramework::Controls::Registry.control_definitions
      controls_json = ::Gitlab::Json.pretty_generate(control_definitions) << "\n"
      File.write(controls_path, controls_json)
      puts "Generated control definitions at #{controls_path}"

      begin
        ComplianceManagement::ComplianceFramework::Controls::Registry.validate_registry!
        puts "Control registry is valid."
      rescue StandardError => e
        puts "WARNING: #{e.message}"
        puts "This may cause database inconsistencies. Please check the controls definition."
      end

      enum_definitions = ComplianceManagement::ComplianceFramework::Controls::Registry.enum_definitions
      puts "\nControl enum values for reference:"
      enum_definitions.sort_by { |_, v| v }.each do |name, value|
        puts "  #{name}: #{value}"
      end

      puts "\nSchema generation complete."
    end
  end
end
