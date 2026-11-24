# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      class Request
        Resource = Struct.new(:type, :namespace, :iid, :referer_url, :ref, keyword_init: true)

        def initialize(args)
          @root_group = Group.find_by_full_path(args[:root_group_path])
          @owner = User.find(args[:user_id])
        end

        def completion(data_row)
          db_record = find_record(data_row.resource)
          resource = adjust_resource(data_row.resource, db_record)
          query = substitute(data_row.query, resource)

          response = query_chat(query, db_record)
          parse_tools_used = parse_tools_used(response)

          {
            ref: data_row.ref,
            query: query,
            resource: resource,
            response: response.response_body,
            tools_used: parse_tools_used
          }
        end

        private

        def adjust_resource(resource, db_record)
          resource = Resource.new(**resource.to_h)

          if %w[epic issue].include?(resource.type)
            resource.namespace = db_record.namespace.full_path
            resource.referer_url = ::Gitlab::UrlBuilder.build(db_record, only_path: false)
          end

          resource
        end

        def find_record(resource)
          case resource.type
          when "epic"
            @root_group.descendants.find_by_full_path("#{@root_group.full_path}/#{resource.namespace}")
                       .epics.find_by_iid(resource.iid)
          when "issue"
            @root_group.all_projects.find_by_full_path("#{@root_group.full_path}/#{resource.namespace}")
                       .issues.find_by_iid(resource.iid)
          end
        end

        def substitute(query, resource)
          format(query, url: resource.referer_url)
        end

        def query_chat(query, db_record)
          data = { content: query, with_clean_history: true }

          ::Gitlab::Duo::Chat::Completions.new(@owner, resource: db_record)
                                          .execute(safe_params: data)
        end

        def parse_tools_used(response)
          tools_used = response&.ai_response&.context&.tools_used

          return unless tools_used.is_a?(Array)

          tools_used
        end
      end
    end
  end
end
