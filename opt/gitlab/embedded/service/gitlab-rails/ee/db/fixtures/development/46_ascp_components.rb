# frozen_string_literal: true

DATA_SENSITIVITY_LEVELS = %w[low medium high].freeze

Gitlab::Seeder.quiet do
  # Seed ASCP components and security contexts for projects that have ASCP scans
  Security::Ascp::Scan.includes(:project).find_each do |scan|
    project = scan.project

    # Create components for each scan
    components = []

    # Authentication component
    auth_component = Security::Ascp::Component.create!(
      project: project,
      scan: scan,
      title: 'Authentication Module',
      sub_directory: "app/auth_#{scan.id}",
      description: 'Handles user authentication and session management',
      expected_user_behavior: 'Users log in with credentials and receive session tokens'
    )
    components << auth_component

    # API component
    api_component = Security::Ascp::Component.create!(
      project: project,
      scan: scan,
      title: 'API Layer',
      sub_directory: "app/api_#{scan.id}",
      description: 'REST API endpoints for client applications',
      expected_user_behavior: 'Clients make authenticated API requests'
    )
    components << api_component

    # Database component
    db_component = Security::Ascp::Component.create!(
      project: project,
      scan: scan,
      title: 'Database Access Layer',
      sub_directory: "app/db_#{scan.id}",
      description: 'Database queries and data persistence',
      expected_user_behavior: 'Data is stored and retrieved securely'
    )
    components << db_component

    # Create dependencies between components
    Security::Ascp::ComponentDependency.create!(
      project: project,
      component: api_component,
      dependency: auth_component
    )

    Security::Ascp::ComponentDependency.create!(
      project: project,
      component: api_component,
      dependency: db_component
    )

    # Create security contexts for each component
    components.each do |component|
      context = Security::Ascp::SecurityContext.create!(
        project: project,
        scan: scan,
        component: component,
        summary: "Security context for #{component.title}",
        authentication_model: 'JWT-based authentication',
        authorization_model: 'Role-based access control',
        data_sensitivity: DATA_SENSITIVITY_LEVELS.sample,
        security_boundary: Security::Ascp::SecurityContext::SECURITY_BOUNDARIES.sample(2)
      )

      # Create security guidelines for each context
      Security::Ascp::SecurityGuideline.create!(
        project: project,
        scan: scan,
        security_context: context,
        name: 'Input Validation Policy',
        operation: 'User input processing',
        legitimate_use: 'Validated and sanitized user input for forms',
        security_boundary: 'Untrusted user input must be validated',
        business_context: 'Protects against injection attacks',
        severity_if_violated: :high
      )

      Security::Ascp::SecurityGuideline.create!(
        project: project,
        scan: scan,
        security_context: context,
        name: 'Data Access Policy',
        operation: 'Database queries',
        legitimate_use: 'Parameterized queries for data retrieval',
        security_boundary: 'No dynamic SQL with user input',
        business_context: 'Prevents SQL injection vulnerabilities',
        severity_if_violated: :critical
      )
    end

    print '.'
  end
end
