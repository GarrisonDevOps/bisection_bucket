# frozen_string_literal: true

module Gitlab
  module Duo
    module Otel
      module GoalTemplates
        ISSUE_TITLE = "Add OpenTelemetry instrumentation"

        RUBY_TEMPLATE = <<~GOAL
          Add OpenTelemetry SDK instrumentation to this Ruby project.

          Requirements:
          1. Add these gems to the Gemfile:
             - opentelemetry-sdk
             - opentelemetry-exporter-otlp
             - opentelemetry-instrumentation-rails
             - opentelemetry-instrumentation-rack

          2. Run `bundle install` to update Gemfile.lock with the new dependencies

          3. Create config/initializers/opentelemetry.rb with SDK configuration:
             - Use ENV['OTEL_EXPORTER_OTLP_ENDPOINT'] for the endpoint (default: http://localhost:4318)
             - Use ENV['OTEL_SERVICE_NAME'] for service name (default to project name)
             - Configure a custom Resource with these attributes:
               - 'gitlab.project.id' from ENV['CI_PROJECT_ID']
               - 'gitlab.project.name' from ENV['CI_PROJECT_NAME']
               - 'service.version' from ENV['CI_COMMIT_SHA']
               - 'deployment.environment.name' from ENV['CI_ENVIRONMENT_NAME']
             - Enable auto-instrumentation with use_all

          4. Do NOT hardcode any secrets, tokens, or endpoints

          5. Include setup instructions in the MR description explaining:
             - How to set the environment variables
             - Note that CI_PROJECT_ID, CI_PROJECT_NAME, CI_COMMIT_SHA, and CI_ENVIRONMENT_NAME are automatically available in GitLab CI/CD
             - How to run a local OTel Collector for testing
        GOAL

        JAVASCRIPT_TEMPLATE = <<~GOAL
          Add OpenTelemetry SDK instrumentation to this Node.js project.

          Requirements:
          1. Add these packages to package.json:
             - @opentelemetry/sdk-node
             - @opentelemetry/auto-instrumentations-node
             - @opentelemetry/exporter-trace-otlp-http

          2. Run `npm install` to update package-lock.json with the new dependencies

          3. Create tracing.js with SDK initialization (loaded via --require flag):
             - Use process.env.OTEL_EXPORTER_OTLP_ENDPOINT for the endpoint (default: http://localhost:4318)
             - Use process.env.OTEL_SERVICE_NAME for service name
             - Configure a custom Resource with these attributes:
               - 'gitlab.project.id' from process.env.CI_PROJECT_ID
               - 'gitlab.project.name' from process.env.CI_PROJECT_NAME
               - 'service.version' from process.env.CI_COMMIT_SHA
               - 'deployment.environment.name' from process.env.CI_ENVIRONMENT_NAME
             - Enable auto-instrumentation with getNodeAutoInstrumentations()

          4. Do NOT hardcode any secrets, tokens, or endpoints

          5. Include setup instructions in the MR description explaining:
             - How to set the environment variables
             - How to load tracing.js on startup (node --require ./tracing.js app.js)
             - Note that CI_PROJECT_ID, CI_PROJECT_NAME, CI_COMMIT_SHA, and CI_ENVIRONMENT_NAME are automatically available in GitLab CI/CD
             - How to run a local OTel Collector for testing
        GOAL

        PYTHON_TEMPLATE = <<~GOAL
          Add OpenTelemetry SDK instrumentation to this Python project.

          Requirements:
          1. Add these packages to requirements.txt:
             - opentelemetry-sdk
             - opentelemetry-exporter-otlp
             - opentelemetry-instrumentation

          2. Run `pip install -r requirements.txt` to install the new dependencies

          3. Create otel_config.py or add to app startup:
             - Use os.environ.get('OTEL_EXPORTER_OTLP_ENDPOINT') for the endpoint (default: http://localhost:4318)
             - Use os.environ.get('OTEL_SERVICE_NAME') for service name
             - Configure a custom Resource with these attributes:
               - 'gitlab.project.id' from os.environ.get('CI_PROJECT_ID')
               - 'gitlab.project.name' from os.environ.get('CI_PROJECT_NAME')
               - 'service.version' from os.environ.get('CI_COMMIT_SHA')
               - 'deployment.environment.name' from os.environ.get('CI_ENVIRONMENT_NAME')
             - Configure TracerProvider with BatchSpanProcessor and OTLPSpanExporter

          4. Do NOT hardcode any secrets, tokens, or endpoints

          5. Include setup instructions in the MR description explaining:
             - How to set the environment variables
             - Note that CI_PROJECT_ID, CI_PROJECT_NAME, CI_COMMIT_SHA, and CI_ENVIRONMENT_NAME are automatically available in GitLab CI/CD
             - How to run a local OTel Collector for testing
        GOAL

        DEFAULT_TEMPLATE = <<~GOAL
          Add OpenTelemetry SDK instrumentation to this project.

          Requirements:
          1. Add the OpenTelemetry SDK and OTLP exporter packages for this project's language

          2. Install the new dependencies using the project's package manager and commit any lock files

          3. Configure the SDK initialization:
             - Use environment variable OTEL_EXPORTER_OTLP_ENDPOINT for the endpoint (default: http://localhost:4318)
             - Use environment variable OTEL_SERVICE_NAME for service name
             - Configure a custom Resource with these attributes:
               - 'gitlab.project.id' from environment variable CI_PROJECT_ID
               - 'gitlab.project.name' from environment variable CI_PROJECT_NAME
               - 'service.version' from environment variable CI_COMMIT_SHA
               - 'deployment.environment.name' from environment variable CI_ENVIRONMENT_NAME
             - Enable auto-instrumentation where available

          4. Do NOT hardcode any secrets, tokens, or endpoints

          5. Include setup instructions in the MR description explaining:
             - How to set the environment variables
             - Note that CI_PROJECT_ID, CI_PROJECT_NAME, CI_COMMIT_SHA, and CI_ENVIRONMENT_NAME are automatically available in GitLab CI/CD
             - How to run a local OTel Collector for testing
        GOAL

        TEMPLATES = {
          'Ruby' => RUBY_TEMPLATE,
          'JavaScript' => JAVASCRIPT_TEMPLATE,
          'TypeScript' => JAVASCRIPT_TEMPLATE,
          'Python' => PYTHON_TEMPLATE
        }.freeze

        class << self
          def issue_title
            ISSUE_TITLE
          end

          def build_description(language)
            TEMPLATES[language] || DEFAULT_TEMPLATE
          end
        end
      end
    end
  end
end
