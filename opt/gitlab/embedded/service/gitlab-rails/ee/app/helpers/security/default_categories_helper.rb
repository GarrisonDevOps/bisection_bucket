# frozen_string_literal: true

module Security
  module DefaultCategoriesHelper
    def self.default_categories
      [
        build_business_impact_category,
        build_application_category,
        build_business_unit_category,
        build_exposure_level_category
      ]
    end

    def self.build_business_impact_category
      Security::Category.new(
        name: 'Business Impact',
        description: 'Classify projects by their importance to business operations.',
        editable_state: :locked,
        template_type: :business_impact,
        multiple_selection: false,
        security_attributes: [
          Security::Attribute.new(
            name: 'Mission Critical',
            template_type: :mission_critical,
            description: 'Essential for core business functions',
            editable_state: :locked,
            color: "#ab6100"
          ),
          Security::Attribute.new(
            name: 'Business Critical',
            template_type: :business_critical,
            description: 'Important for key business operations',
            editable_state: :locked,
            color: "#c17d10"
          ),
          Security::Attribute.new(
            name: 'Business Operational',
            template_type: :business_operational,
            description: 'Standard operational systems',
            editable_state: :locked,
            color: "#9d6e2b"
          ),
          Security::Attribute.new(
            name: 'Business Administrative',
            template_type: :business_administrative,
            description: 'Supporting administrative functions',
            editable_state: :locked,
            color: "#e9be74"
          ),
          Security::Attribute.new(
            name: 'Non-essential',
            template_type: :non_essential,
            description: 'Minimal business impact',
            editable_state: :locked,
            color: "#f5d9a8"
          )
        ]
      )
    end

    def self.build_application_category
      Security::Category.new(
        name: 'Application',
        description: 'Categorize projects by application type and technology stack.',
        editable_state: :editable_attributes,
        template_type: :application,
        multiple_selection: false,
        security_attributes: []
      )
    end

    def self.build_business_unit_category
      Security::Category.new(
        name: 'Business Unit',
        description: 'Organize projects by owning teams and departments.',
        editable_state: :editable_attributes,
        template_type: :business_unit,
        multiple_selection: false,
        security_attributes: []
      )
    end

    def self.build_exposure_level_category
      Security::Category.new(
        name: 'Exposure level',
        description: 'Tag systems based on network accessibility and exposure risk.',
        editable_state: :editable_attributes,
        template_type: :exposure,
        multiple_selection: false,
        security_attributes: []
      )
    end
  end
end
