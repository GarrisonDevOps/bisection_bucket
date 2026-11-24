# frozen_string_literal: true

module API
  module Entities
    module MergeRequests
      class StatusCheck < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
        expose :name, documentation: { type: 'String', example: 'QA' }
        expose :external_url, documentation: { type: 'String', example: 'https://www.example.com' }
        expose :status, documentation: { type: 'String', example: 'passed' }

        def status
          object.status(options[:merge_request], options[:sha])
        end

        def external_url
          project = options[:merge_request].project

          if Ability.allowed?(options[:current_user], :read_merge_request_status_check_url, project)
            return object.external_url[/[^?]+/]
          end

          ''
        end
      end
    end
  end
end
